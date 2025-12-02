# ctlint

CT compliance linter

## Intended uses

- Certification Authorities: Pre-issuance linting of precertificates and certificates.

- Interested Parties: Post-issuance conformance checking.

## Features

- Determines which CT logs are currently or once approved for each CT Policy by bundling and parsing the Chrome [all_logs_list.json](https://googlechrome.github.io/CertificateTransparency/log_lists.html) and Apple [current_log_list.json](https://support.apple.com/en-us/103214) log lists.

- Audits certificates against the requirements of the [Chrome CT Policy](https://googlechrome.github.io/CertificateTransparency/ct_policy.html) and the [Apple CT Policy](https://support.apple.com/en-us/103214), to ensure that embedded SCT lists contain a sufficient quantity and variety of SCTs from approved CT logs.

- Checks that certificates expire within the temporal intervals of the logs that supplied the precertificate SCTs embedded in those certificates.

- Verifies signatures on precertificate SCTs embedded in certificates, using bundled CCADB data to determine each SCT's issuer_key_hash field.

- Validates syntax and usage of RFC6962 X.509 extensions appearing in certificates and precertificates.

## Why you need ctlint

Here are some real-world examples of CT-related mishaps that `ctlint` can detect:

- [Precertificate included an SCT list](https://bugzilla.mozilla.org/show_bug.cgi?id=1815534)

- [SCTs signed using the wrong key](https://groups.google.com/a/chromium.org/g/ct-policy/c/gsC6NblTxyQ/m/ARKimL4NBgAJ)

- [Insufficient log operator diversity amongst SCTs embedded in a certificate](https://crt.sh/?id=14593225463)

- [SCTs corrupted by a CA and then embedded in certificates](https://bugzilla.mozilla.org/show_bug.cgi?id=1952591)

- [Invalid SCTs returned by a log and then embedded in certificates](https://bugzilla.mozilla.org/show_bug.cgi?id=1969296)

- [Certificates expire outside the temporal interval of a log that supplied SCTs embedded in those certificates](https://bugzilla.mozilla.org/show_bug.cgi?id=1970259)

- [SCTs obtained from logs that are not yet Usable and then embedded in certificates](https://groups.google.com/a/chromium.org/g/ct-policy/c/VGgpEj92dCk/m/Y_rN35ZKBwAJ)

## Caveats

- After a log's temporal interval expires, the log is removed from the various log lists. Consequently, `ctlint` can only audit CT Policy compliance of SCTs embedded in certificates that have not yet expired.
