package ctlint

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/crtsh/ccadb_data"
	ctgo "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/loglist3"
	"github.com/google/certificate-transparency-go/x509"
)

func checkSCTListCompliance(cert *x509.Certificate, sha256IssuerSPKI *[sha256.Size]byte, scts []*ctgo.SignedCertificateTimestamp) []string {
	var findings []string

	tbsCert, err := x509.RemoveSCTList(cert.RawTBSCertificate)
	if err != nil {
		return []string{"E: Cannot remove SCT List extension to derive TBSCertificate"}
	}

	for _, sct := range scts {
		if sha256IssuerSPKI == nil {
			if encoded, found := ccadb_data.GetIssuerSPKISHA256ByKeyIdentifier(base64.StdEncoding.EncodeToString(cert.AuthorityKeyId)); found {
				sha256IssuerSPKI = &encoded
			} else {
				return []string{"W: Cannot verify SCT signature without issuer SPKI, which could not be found in the available CCADB data"}
			}
		}

		findings = append(findings, verifySCT(tbsCert, sha256IssuerSPKI, sct)...)

		if ti := temporalIntervalMap[sct.LogID.KeyID]; ti != nil {
			if cert.NotAfter.Before(ti.StartInclusive) || !cert.NotAfter.Before(ti.EndExclusive) {
				findings = append(findings, "E: Certificate expires outside log's temporal interval")
			}
		}
	}

	if time.Now().After(cert.NotAfter) {
		findings = append(findings, "N: SCT list in expired certificate not checked for CT Policy compliance")
	} else {
		findings = append(findings, checkSCTListComplianceWithCTPolicy(cert, scts, gstaticV3AllLogsList, "Chrome")...)
		findings = append(findings, checkSCTListComplianceWithCTPolicy(cert, scts, appleCurrentLogList, "Apple")...)
		findings = append(findings, checkSCTListComplianceWithCTPolicy(cert, scts, mozillaV3KnownLogsList, "Mozilla")...)
	}

	return findings
}

func findLogByKeyHash(keyHash [sha256.Size]byte, logList *loglist3.LogList) (*loglist3.Log, string, bool) {
	for _, operator := range logList.Operators {
		for _, log := range operator.Logs {
			if bytes.Equal(log.LogID, keyHash[:]) {
				return log, operator.Name, true
			}
		}
	}

	for _, operator := range logList.Operators {
		for _, tiledLog := range operator.TiledLogs {
			if bytes.Equal(tiledLog.LogID, keyHash[:]) {
				return &loglist3.Log{
					State:            tiledLog.State,
					TemporalInterval: tiledLog.TemporalInterval,
				}, operator.Name, false
			}
		}
	}

	return nil, "", false
}

func checkSCTListComplianceWithCTPolicy(cert *x509.Certificate, scts []*ctgo.SignedCertificateTimestamp, logList *loglist3.LogList, ctPolicyName string) []string {
	var findings []string

	// Chrome CT Policy: "Chrome will enforce CT so long as the log_list_timestamp of the freshest version of the log list Chrome stores is within the past 70 days (10 weeks), and uses a log list format that Chrome understands."
	// Mozilla CT Policy: "This information has a 10 week expiration time. That is, if 10 weeks have passed since the information has been updated (typically by updating Firefox itself), the implementation will no longer enforce certificate transparency."
	switch ctPolicyName {
	case "Chrome", "Mozilla":
		if logList.LogListTimestamp.Add(70 * 24 * time.Hour).Before(time.Now()) {
			findings = append(findings, fmt.Sprintf("F: The available %s log list is older than 70 days: Update ctlint!", ctPolicyName))
		}
	}

	var currentlyApprovedLogs, onceApprovedLogs []*loglist3.Log
	previousOperatorName := ""
	atLeastTwoOperators := false
	nSCTsFromQualifiedLogs := 0
	nSCTsFromRFC6962Logs := 0
	for _, sct := range scts {
		if ctLog, logOperatorName, isRFC6962Log := findLogByKeyHash(sct.LogID.KeyID, logList); ctLog != nil && ctLog.State != nil {
			if (ctLog.State.Usable != nil && !ctLog.State.Usable.Timestamp.Before(time.Now())) || ctLog.State.ReadOnly != nil {
				currentlyApprovedLogs = append(currentlyApprovedLogs, ctLog)
			} else if ctLog.State.Qualified != nil && !ctLog.State.Qualified.Timestamp.Before(time.Now()) {
				nSCTsFromQualifiedLogs++
				currentlyApprovedLogs = append(currentlyApprovedLogs, ctLog)
			} else if ctLog.State.Retired != nil {
				if ctLog.State.Retired.Timestamp.After(time.UnixMilli(int64(sct.Timestamp))) {
					onceApprovedLogs = append(onceApprovedLogs, ctLog)
				} else {
					continue
				}
			} else {
				continue
			}

			if previousOperatorName != "" && logOperatorName != previousOperatorName {
				atLeastTwoOperators = true
			}
			previousOperatorName = logOperatorName

			if isRFC6962Log {
				nSCTsFromRFC6962Logs++
			}
		}
	}

	// Chrome CT Policy: "1. At least one Embedded SCT from a CT log that was Qualified, Usable, or ReadOnly at the time of check; and"
	// Apple CT Policy: "At least one embedded SCT from a currently approved log and"
	// Mozilla CT Policy: "At least 1 of those SCTs must be from a log that was Admissible at the time of verification"
	if len(currentlyApprovedLogs) < 1 {
		findings = append(findings, fmt.Sprintf("W: SCT list contains no SCTs from logs currently approved by the %s CT Policy", ctPolicyName))
	}

	// Chrome CT Policy: "2. There are Embedded SCTs from at least N distinct CT logs that were Qualified, Usable, ReadOnly, or Retired at the time of check...
	//                   "...Number of SCTs from distinct CT logs: '<= 180 days' => 2; '> 180 days' => 3...; and"
	// Apple CT Policy: "The Number of embedded SCTs required is based on certificate lifetime...
	//                  "...# of SCTs from distinct logs: '180 days or less' => 2; '181 to 398 days' => 3"
	// Mozilla CT Policy: 'For embedded SCTs, "sufficient" means at least N SCTs from distinct logs that were Admissible or Retired at the time of verification, where N is 2 for certificates with a lifetime of 180 days or less, and 3 otherwise.'
	nApprovedSCTsRequired := 2
	if cert.NotAfter.Sub(cert.NotBefore) > 180*24*time.Hour {
		nApprovedSCTsRequired++
	}
	if len(currentlyApprovedLogs)+len(onceApprovedLogs) < nApprovedSCTsRequired {
		findings = append(findings, fmt.Sprintf("W: SCT list contains fewer approved SCTs than required by the %s CT Policy", ctPolicyName))
	} else if len(currentlyApprovedLogs)+len(onceApprovedLogs)-nSCTsFromQualifiedLogs < nApprovedSCTsRequired {
		switch ctPolicyName {
		case "Mozilla":
			findings = append(findings, fmt.Sprintf("W: SCT list satisfies the %s CT Policy using at least 1 SCT from an Admissible log that is not yet broadly usable", ctPolicyName))
		default:
			findings = append(findings, fmt.Sprintf("W: SCT list satisfies the %s CT Policy using at least 1 SCT from a Qualified log that is not yet Usable", ctPolicyName))
		}
	}

	// Chrome CT Policy: "3. Among the SCTs satisfying requirement 2, at least two SCTs must be issued from distinct CT log operators as recognized by Chrome; and"
	// Apple CT Policy: "Maximum # of SCTs per log operator which count towards the SCT requirement: '180 days or less' => 1; '181 to 398 days' => 2"
	// Mozilla CT Policy: "Among those SCTs, at least 2 must be from distinct log operators."
	if !atLeastTwoOperators {
		findings = append(findings, fmt.Sprintf("W: SCT list contains SCTs from fewer log operators than required by the %s CT Policy", ctPolicyName))
	}

	// Chrome CT Policy: "4. Before April 15, 2026: Among the SCTs satisfying requirement 2, at least one SCT must be issued from a log recognized by Chrome as being RFC6962-compliant."
	// Apple CT Policy: "At least one SCT must be issued from a log compliant with RFC 6962."
	if nSCTsFromRFC6962Logs < 1 {
		var enforceOneRFC6962LogPolicy bool
		switch ctPolicyName {
		case "Chrome":
			enforceOneRFC6962LogPolicy = time.Now().Before(time.Date(2026, 4, 15, 0, 0, 0, 0, time.UTC))
		case "Apple":
			enforceOneRFC6962LogPolicy = true
		case "Mozilla":
			enforceOneRFC6962LogPolicy = time.Now().Before(time.Date(2026, 2, 10, 9, 45, 58, 0, time.UTC)) // Push timestamp of https://hg-edge.mozilla.org/mozilla-central/rev/afcac3008cbb plus 70 days.
		}

		if enforceOneRFC6962LogPolicy {
			findings = append(findings, fmt.Sprintf("W: SCT list contains fewer SCTs from RFC6962-compliant logs than required by the %s CT Policy", ctPolicyName))
		}
	}

	return findings
}
