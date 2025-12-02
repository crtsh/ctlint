package ctlint

import (
	"crypto/sha256"
	"time"

	ctgo "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/asn1"
	"github.com/google/certificate-transparency-go/tls"
	"github.com/google/certificate-transparency-go/x509"
	"github.com/google/certificate-transparency-go/x509/pkix"
	"github.com/google/certificate-transparency-go/x509util"
)

func checkSCTListExtension(cert *x509.Certificate, sha256IssuerSPKI *[sha256.Size]byte, sctListExt pkix.Extension) []string {
	var findings []string

	var sctListExtValue []byte
	var sctList x509.SignedCertificateTimestampList
	var scts []*ctgo.SignedCertificateTimestamp
	if rest, err := asn1.Unmarshal(sctListExt.Value, &sctListExtValue); err != nil {
		findings = append(findings, "E: SCT list extension could not be parsed")
	} else if len(rest) != 0 {
		findings = append(findings, "E: SCT list extension contains trailing data")
	} else if rest, err := tls.Unmarshal(sctListExtValue, &sctList); err != nil {
		findings = append(findings, "E: SCT list could not be parsed")
	} else if len(rest) != 0 {
		findings = append(findings, "E: SCT list contains trailing data")
	} else if scts, err = x509util.ParseSCTsFromSCTList(&sctList); err != nil {
		findings = append(findings, "E: SCTs could not be parsed from SCT list")
	} else if time.Now().After(cert.NotAfter) {
		findings = append(findings, "N: SCT list in expired certificate not checked for CT Policy compliance")
	} else {
		findings = append(findings, checkSCTListCompliance(cert, sha256IssuerSPKI, scts)...)
	}

	return findings
}
