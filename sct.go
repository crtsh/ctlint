package ctlint

import (
	"crypto/sha256"

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
		return []string{"E: An SCT has an invalid signature"}
	}

	return []string{"I: An SCT has a valid signature"}
}
