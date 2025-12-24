package ctlint

import (
	"crypto/sha256"

	"github.com/google/certificate-transparency-go/asn1"
	"github.com/google/certificate-transparency-go/x509"
)

var OIDExtensionOCSPCTSCT = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 4, 5}

func CheckCertificate(cert *x509.Certificate, sha256IssuerSPKI *[sha256.Size]byte) []string {
	var findings []string

	if cert == nil {
		findings = append(findings, "E: Certificate not provided")
	} else if !cert.IsCA {
		sctListExtCount := 0
		for _, ext := range cert.Extensions {
			if ext.Id.Equal(x509.OIDExtensionCTSCT) {
				sctListExtCount++
				if sctListExtCount > 1 {
					findings = append(findings, "E: Multiple SCT list extensions are present")
				}
				findings = append(findings, checkSCTListExtension(cert, sha256IssuerSPKI, ext)...)
			} else if ext.Id.Equal(x509.OIDExtensionCTPoison) {
				findings = append(findings, "E: Precertificate 'poison' extension is present")
			} else if ext.Id.Equal(OIDExtensionOCSPCTSCT) {
				findings = append(findings, "E: OCSP SCT list extension is present")
			}
		}

		if sctListExtCount == 0 {
			for _, eku := range cert.ExtKeyUsage {
				if eku == x509.ExtKeyUsageServerAuth {
					findings = append(findings, "N: SCT list extension is absent")
					break
				}
			}
		} else {
			findings = append([]string{"I: Certificate with embedded SCT list identified"}, findings...)
		}
	} else {
		for _, eku := range cert.ExtKeyUsage {
			if eku == x509.ExtKeyUsageCertificateTransparency {
				findings = append(findings, "I: Precertificate Signing Certificate identified")
				break
			}
		}
	}

	return findings
}
