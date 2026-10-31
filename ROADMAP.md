# Roadmap

bx supports local vault access, multiple accounts, TOTP login, item writes,
folders, collections, attachments, JSON output, shell completion, and password
and passphrase generation.

Planned improvements:

- Broader integration coverage against Bitwarden and Vaultwarden, including
  cross-client attachment and ownership-change tests.
- Additional two-factor authentication methods.
- Streaming large attachments with bounded memory.
- More consistent command error handling and structured scripting support.
- Reproducible signed releases and platform coverage.

Security and data preservation take priority over new features. See
[SECURITY.md](SECURITY.md) for the current assumptions and limitations.
