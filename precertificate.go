package ctlint

import (
	"bytes"

	"github.com/google/certificate-transparency-go/x509"
)

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
		}
	}

	return findings
}
