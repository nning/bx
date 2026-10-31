# Security review guide

The security model and supported cryptographic formats are described in
[SECURITY.md](../SECURITY.md). This guide records review areas rather than
claiming an independent audit or a guarantee of correctness.

Review authentication, refreshes and file transfers for HTTPS enforcement and
credential isolation. Named accounts must not inherit another account's tokens
or keys. Redirects must preserve the request origin.

Check cryptographic interoperability against independent Bitwarden format
vectors. Attachments use a type byte, IV, MAC and ciphertext; direct uploads
use the API multipart endpoint, while downloads first retrieve metadata.
Test both upload and download against an isolated server before release.

Exercise edits and ownership changes with unknown fields, item keys, passkeys,
attachments and password history. Confirm that cache updates preserve encrypted
fields and that conflicts stop a write.

Inspect file permissions, atomic replacement, editor files and clipboard behavior.
Run `make ci`, review dependency vulnerability results and scan the proposed
release tree for secrets. Release artifacts must be built from the exact
validated commit. Keep personal vault data out of tests and documentation.
