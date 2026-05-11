package ctlint

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"time"

	"github.com/crtsh/ctloglists"
	ctgo "github.com/google/certificate-transparency-go"
)

func verifySCT(tbsCert []byte, sha256IssuerSPKI *[sha256.Size]byte, sct *ctgo.SignedCertificateTimestamp) []string {
	if sct.SCTVersion != ctgo.V1 {
		return []string{"E: SCT version is not V1"}
	}

	var findings []string
	if time.UnixMilli(int64(sct.Timestamp)).After(time.Now().Add(time.Second)) {
		findings = append(findings, "E: SCT timestamp is in the future")
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

	sv := ctloglists.LogSignatureVerifierMap[([sha256.Size]byte)(sct.LogID.KeyID)]
	if sv == nil {
		return append(findings, "N: SCT is from an unknown log")
	}

	// Get the log description, for display purposes.  The crt.sh, gstatic, and mimic log lists should between them cover all known SCT signers.
	log, operator, _ := findLogByKeyHash(sct.LogID.KeyID, ctloglists.CrtshV3All)
	if log == nil {
		log, operator, _ = findLogByKeyHash(sct.LogID.KeyID, ctloglists.GstaticV3All)
	}
	if log == nil {
		log, operator, _ = findLogByKeyHash(sct.LogID.KeyID, ctloglists.LogMimics)
	}

	// Ensure that the Operator name is prepended to the log description, if not already present, for display purposes.
	description := ""
	if log != nil {
		description = "(" + log.Description + ")"
		if operator != "" && !strings.Contains(description, operator) {
			description = operator + " " + description
		}
	}

	err := sv.VerifySCTSignature(*sct, ctgo.LogEntry{Leaf: merkleTreeLeaf})
	if err != nil {
		if log != nil {
			return append(findings, fmt.Sprintf("E: SCT has an invalid signature purporting to be from %s", description))
		} else {
			return append(findings, "E: SCT has an invalid signature")
		}
	}

	if log != nil {
		return append(findings, fmt.Sprintf("I: SCT has a valid signature from %s", description))
	} else {
		return append(findings, "I: SCT has a valid signature")
	}
}
