package ctlint

import (
	"github.com/google/certificate-transparency-go/asn1"
	"github.com/google/certificate-transparency-go/x509"
)

var (
	// OidExtKeyUsageBrandIndicatorForMessageIdentification is Extended Key Usage (EKU) for id-kp-BrandIndicatorforMessageIdentification used for MCs
	OidExtKeyUsageBrandIndicatorForMessageIdentification = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 31}
)

func IsServerAuthCert(cert *x509.Certificate) bool {
	for _, eku := range cert.ExtKeyUsage {
		if eku == x509.ExtKeyUsageAny || eku == x509.ExtKeyUsageServerAuth {
			return true
		}
	}
	return false
}

func IsMarkCert(cert *x509.Certificate) bool {
	for _, unknownEKU := range cert.UnknownExtKeyUsage {
		if unknownEKU.Equal(OidExtKeyUsageBrandIndicatorForMessageIdentification) {
			return true
		}
	}
	return false
}
