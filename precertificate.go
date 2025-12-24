package ctlint

import (
	"bytes"
	_ "embed"
	"strings"
	"time"

	"github.com/google/certificate-transparency-go/x509"
)

//go:embed files/precert_signing_ca_commonnames.txt
var precertSigningCACNs string

var precertSigningCACNMap map[string]struct{}

func init() {
	precertSigningCACNMap = make(map[string]struct{})

	for cn := range strings.SplitSeq(precertSigningCACNs, "\n") {
		cn = strings.TrimSpace(cn)
		if cn != "" {
			precertSigningCACNMap[cn] = struct{}{}
		}
	}
}

func CheckPrecertificate(precert *x509.Certificate) []string {
	var findings []string

	if precert == nil {
		findings = append(findings, "E: Precertificate not provided")
	} else {
		poisonExtCount := 0
		for _, ext := range precert.Extensions {
			if ext.Id.Equal(x509.OIDExtensionCTPoison) {
				poisonExtCount++
				if poisonExtCount > 1 {
					findings = append(findings, "E: Multiple Precertificate 'poison' extensions are present")
				}
				if !ext.Critical {
					findings = append(findings, "E: Precertificate 'poison' extension is not critical")
				}
				if !bytes.Equal(ext.Value, []byte{0x05, 0x00}) {
					findings = append(findings, "E: Precertificate 'poison' extension has incorrect contents")
				}
			} else if ext.Id.Equal(x509.OIDExtensionCTSCT) {
				findings = append(findings, "E: SCT list extension is present")
			} else if ext.Id.Equal(OIDExtensionOCSPCTSCT) {
				findings = append(findings, "E: OCSP SCT list extension is present")
			}
		}

		if poisonExtCount == 0 {
			findings = append(findings, "E: Precertificate 'poison' extension is absent")
		} else {
			findings = append([]string{"I: Precertificate identified"}, findings...)
		}

		if _, found := precertSigningCACNMap[precert.Issuer.CommonName]; found {
			if precert.NotBefore.Before(time.Date(2026, 3, 15, 0, 0, 0, 0, time.UTC)) {
				findings = append(findings, "I: Precertificate issued by a Precertificate Signing CA")
			} else {
				findings = append(findings, "E: Precertificate issued by a Precertificate Signing CA after March 15, 2026")
			}
		}
	}

	return findings
}
