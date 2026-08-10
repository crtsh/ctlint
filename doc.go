// Package ctlint lints X.509 certificates and precertificates for compliance
// with Certificate Transparency (CT) policies.
//
// It checks embedded SCT lists against the requirements of applicable CT
// policies (Chrome, Apple, Mozilla for server authentication certificates;
// Mark Certificate Guidelines for BIMI mark certificates), verifies SCT
// signatures using bundled CCADB data, and validates RFC 6962 extension syntax.
//
// # Certificate Linting
//
// Use [CheckCertificate] to lint a certificate (or precertificate signing
// certificate). It examines RFC 6962 extensions, verifies embedded SCT
// signatures, and audits the SCT list for CT policy compliance.
//
// # Precertificate Linting
//
// Use [CheckPrecertificate] to lint a precertificate. It validates the
// poison extension and checks for disallowed extensions and issuance from
// a Precertificate Signing CA beyond the TLS BRs sunset date.
//
// # Findings
//
// Both functions return a slice of human-readable finding strings. Each
// finding is prefixed with a severity level:
//
//   - "E:" — Error. A conformance violation.
//   - "W:" — Warning. Likely non-compliant but may depend on timing or log state.
//   - "N:" — Notice. Informational but noteworthy (e.g., absent SCT list, expired certificate).
//   - "I:" — Info. Informational context (e.g., certificate type identified, valid SCT signature).
//   - "F:" — Fatal. The linter's own data is stale; update ctlint.
package ctlint
