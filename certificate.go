package ctlint

import (
	"crypto/sha256"
	"fmt"

	"github.com/google/certificate-transparency-go/asn1"
	"github.com/google/certificate-transparency-go/x509"
)

// CTPolicyGroup identifies the CT policy category applicable to a certificate.
type CTPolicyGroup int

const (
	unknown CTPolicyGroup = iota
	// ServerAuthenticationCertificate indicates a TLS server authentication certificate,
	// subject to Chrome, Apple, and Mozilla CT policies.
	ServerAuthenticationCertificate
	// MarkCertificate indicates a BIMI mark certificate, subject to the
	// Mark Certificate Guidelines CT requirements.
	MarkCertificate
)

// OIDExtensionOCSPCTSCT is the OID for the OCSP CT SCT extension (1.3.6.1.4.1.11129.2.4.5).
var OIDExtensionOCSPCTSCT = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 4, 5}

// OIDEKUBrandIndicatorforMessageIdentification is the Extended Key Usage OID for BIMI (1.3.6.1.5.5.7.3.31).
var OIDEKUBrandIndicatorforMessageIdentification asn1.ObjectIdentifier = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 31}

// CheckCertificate lints a certificate for CT compliance. It validates RFC 6962
// extension usage, verifies embedded SCT signatures, and checks the SCT list
// against applicable CT policies.
//
// sha256IssuerSPKI is the SHA-256 hash of the issuer's SubjectPublicKeyInfo,
// used to verify SCT signatures. If nil, the function attempts to look it up
// from bundled CCADB data using the certificate's Authority Key Identifier.
//
// policyGroup_optional overrides automatic policy group detection. When omitted,
// the policy group is inferred from the certificate's Extended Key Usage.
func CheckCertificate(cert *x509.Certificate, sha256IssuerSPKI *[sha256.Size]byte, policyGroup_optional ...CTPolicyGroup) []string {
	var findings []string

	if cert == nil {
		findings = append(findings, "E: Certificate not provided")
	} else if !cert.IsCA {
		policyGroup, policyGroupDescription := getPolicyGroup(cert, policyGroup_optional)
		sctListExtCount := 0
		for _, ext := range cert.Extensions {
			if ext.Id.Equal(x509.OIDExtensionCTSCT) {
				sctListExtCount++
				if sctListExtCount > 1 {
					findings = append(findings, "E: Multiple SCT list extensions are present")
				}
				findings = append(findings, checkSCTListExtension(cert, policyGroup, sha256IssuerSPKI, ext)...)
			} else if ext.Id.Equal(x509.OIDExtensionCTPoison) {
				findings = append(findings, "E: Precertificate 'poison' extension is present")
			} else if ext.Id.Equal(OIDExtensionOCSPCTSCT) {
				findings = append(findings, "E: OCSP SCT list extension is present")
			}
		}

		if sctListExtCount == 0 {
			switch policyGroup {
			case ServerAuthenticationCertificate:
				findings = append(findings, fmt.Sprintf("N: SCT list extension is absent in this %s", policyGroupDescription))
			case MarkCertificate:
				findings = append(findings, fmt.Sprintf("E: SCT list extension is absent in this %s", policyGroupDescription))
			default:
				findings = append(findings, fmt.Sprintf("I: No CT policies apply to this %s", policyGroupDescription))
			}
		} else {
			findings = append([]string{fmt.Sprintf("I: %s with embedded SCT list identified", policyGroupDescription)}, findings...)
		}
	} else {
		for _, eku := range cert.ExtKeyUsage {
			if eku == x509.ExtKeyUsageCertificateTransparency {
				findings = append([]string{"I: Precertificate Signing Certificate identified"}, findings...)
				break
			}
		}
	}

	return findings
}

func getPolicyGroup(cert *x509.Certificate, policyGroup_optional []CTPolicyGroup) (CTPolicyGroup, string) {
	policyGroup := detectPolicyGroup(cert, policyGroup_optional)
	switch policyGroup {
	case ServerAuthenticationCertificate:
		return policyGroup, "Server Authentication Certificate"
	case MarkCertificate:
		return policyGroup, "Mark Certificate"
	default:
		return policyGroup, "Certificate"
	}
}

func detectPolicyGroup(cert *x509.Certificate, policyGroup_optional []CTPolicyGroup) CTPolicyGroup {
	if len(policyGroup_optional) > 0 {
		return policyGroup_optional[0]
	}

	for _, eku := range cert.ExtKeyUsage {
		switch eku {
		case x509.ExtKeyUsageAny, x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageMicrosoftServerGatedCrypto, x509.ExtKeyUsageNetscapeServerGatedCrypto:
			return ServerAuthenticationCertificate
		}
	}

	for _, unknownEKU := range cert.UnknownExtKeyUsage {
		if unknownEKU.Equal(OIDEKUBrandIndicatorforMessageIdentification) {
			return MarkCertificate
		}
	}

	return unknown
}
