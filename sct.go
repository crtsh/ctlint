package ctlint

import (
	"crypto/sha256"
	"fmt"

	ctgo "github.com/google/certificate-transparency-go"
)

func verifySCT(tbsCert []byte, sha256IssuerSPKI *[sha256.Size]byte, sct *ctgo.SignedCertificateTimestamp) []string {
	if sct.SCTVersion != ctgo.V1 {
		return []string{"E: SCT version is not V1"}
	}

	merkleTreeLeaf := ctgo.MerkleTreeLeaf{
		Version:  ctgo.V1,
		LeafType: ctgo.TimestampedEntryLeafType,
		TimestampedEntry: &ctgo.TimestampedEntry{
			EntryType: ctgo.PrecertLogEntryType,
			Timestamp: sct.Timestamp,
			PrecertEntry: &ctgo.PreCert{
				IssuerKeyHash:  *sha256IssuerSPKI,
				TBSCertificate: tbsCert,
			},
			Extensions: sct.Extensions,
		},
	}

	sv := logSignatureVerifierMap[([sha256.Size]byte)(sct.LogID.KeyID)]
	if sv == nil {
		return []string{"B: Signature verifier is not available"}
	}

	err := sv.VerifySCTSignature(*sct, ctgo.LogEntry{Leaf: merkleTreeLeaf})
	if err != nil {
		return []string{"E: SCT has an invalid signature"}
	}

	// Get the log description, for display purposes.  The crt.sh and gstatic log lists should cover all known logs between them.
	log, _, _ := findLogByKeyHash(sct.LogID.KeyID, crtshV3AllLogsList)
	if log == nil {
		log, _, _ = findLogByKeyHash(sct.LogID.KeyID, gstaticV3AllLogsList)
	}

	if log != nil {
		return []string{fmt.Sprintf("I: SCT has a valid signature from %s", log.Description)}
	} else {
		return []string{"I: SCT has a valid signature"}
	}
}
