package main

import (
	"crypto/sha256"
	"fmt"
	"os"

	"github.com/crtsh/ctlint"

	"github.com/crtsh/ctloglists"
	"github.com/google/certificate-transparency-go/x509"
)

func main() {
	exitCode := -1
	defer func() { os.Exit(int(exitCode)) }()

	if len(os.Args) < 2 || len(os.Args) > 3 {
		fmt.Printf("Usage: %s <cert_filename> [<issuer_cert_filename>]\n", os.Args[0])
		return
	}

	var err error
	if err = ctloglists.LoadLogLists(); err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	var infile []byte
	infile, err = os.ReadFile(os.Args[1])
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	var issuerCert *x509.Certificate
	var sha256IssuerSPKI *[sha256.Size]byte
	if len(os.Args) == 3 {
		var issuercertfile []byte
		issuercertfile, err = os.ReadFile(os.Args[2])
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			return
		}
		if issuerCert, err = x509.ParseCertificate(issuercertfile); err != nil {
			fmt.Printf("Error: %v\n", err)
			return
		}
		spkiSHA256 := sha256.Sum256(issuerCert.RawSubjectPublicKeyInfo)
		sha256IssuerSPKI = &spkiSHA256
	}

	var findings []string
	cert, err := x509.ParseCertificate(infile)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	} else if cert.IsPrecertificate() {
		findings = ctlint.CheckPrecertificate(cert)
	} else {
		findings = ctlint.CheckCertificate(cert, sha256IssuerSPKI)
	}

	for _, finding := range findings {
		fmt.Println(finding)
	}

	exitCode = 0
}
