# bx

> [!WARNING]
> **Developed with GitHub Copilot with different models**

A fast, lightweight CLI client for [Bitwarden](https://bitwarden.com) and self-hosted [Vaultwarden](https://github.com/dani-garcia/vaultwarden) instances, written in Go.

## Getting Started

Run the interactive setup wizard — it walks you through all three steps at once:

```bash
bx setup
```

That's it. The wizard will ask for your server URL, email address, and master password (plus a 2FA code if your account requires it), then fetch and cache your vault locally.

### Manual setup

If you prefer to run each step individually:

**1. Add an account** — `bx` will prompt for the server URL, email, and master password:

```bash
bx account add myaccount
```

**2. Sync your vault:**

```bash
bx fetch
```

**3. You're ready.** Some common commands:

```bash
bx list                     # list all vault items (ID, TYPE, NAME, USERNAME, PASSKEY)
bx list --deleted           # list Trash items (soft-deleted)
bx list --json              # list as JSON (stable schema, see below)
bx get "GitHub"             # show an item's details (match by name)
bx get github.com           # show an item's details (match by URL)
bx get "GitHub" --copy      # copy the password to clipboard
bx get "GitHub" -P          # print just the password (with -c: copy just the password)
bx get "Bank" -c -k iban    # copy a custom field by name (case-insensitive; exact match wins, substring otherwise)
bx get "Google" --totp      # generate a TOTP code
bx get "GitHub" --json      # print the record as JSON
bx get "GitHub" --history   # print the item's previous passwords, newest first
bx show "GitHub"            # alias for get
```

### JSON output

`bx list --json` and `bx get --json` are stable interfaces for scripts:
fields are only ever added, absent values are omitted, and item types are
spelled `login`, `note`, `card`, `identity` and `ssh-key`.  Every value is
decrypted with the item's key, so the output carries secrets in plaintext —
handle it with the same care as the terminal output.  A record that cannot be
fully decrypted aborts with an error instead of printing a partial one.

### Write operations

Create, edit, and delete items directly on the server:

```bash
# Create a new login item
bx create --name "GitHub" --username "alice" --url "https://github.com"
# Omit --password to be prompted securely with no echo, or pipe it in with
# --password-stdin; a password passed with --password is visible to other
# processes, and bx warns about it.
# --generate creates a random password and copies it to the clipboard.
# 'bx new' is an alias for 'bx create'

# Edit individual fields (only changed flags are applied)
bx edit "GitHub" --password newpass

# Add a URL to an existing item (additive — existing URLs are kept)
bx edit "GitHub" --url "https://github.com/login"

# Remove a specific URL from an item
bx edit "GitHub" --remove-url "https://old.example.com"

# Edit the item in $VISUAL/$EDITOR, including custom fields, one per line:
#   field Recovery code: abc-123      (text)
#   hidden PIN: 1234                  (hidden)
#   boolean Active: true              (checkbox)
#   linked Login: username            (linked to username or password)
bx edit "GitHub" -i

# Move an item to the Trash
bx delete "GitHub"

# List Trash items to confirm
bx list --deleted

# Permanently delete (item must already be in Trash)
bx delete "GitHub" --permanent

# Restore an item from the Trash
bx restore "GitHub"

# Manage folders
bx folder list
bx folder create --name "Work"
bx folder rename "Work" --name "Company"
bx folder delete "Work"

# Attachments
bx attachment list "GitHub"              # list an item's attachments
bx attachment get "GitHub" contract.pdf  # download and decrypt (--output/-o for a path, "-" for stdout)
bx attachment add "GitHub" scan.pdf      # attach a file (uploaded encrypted)
```

### Item types

bx supports all item types: logins, secure notes, cards, identities and SSH
keys.  `bx list` marks the type of every item, and `bx get --print` shows the
type-specific fields.  New items are created with `--type`:

```bash
# A secure note (notes only)
bx create --type note --name "Recovery codes" --notes "…"

# A card (--cardholder, --brand, --number, --exp-month, --exp-year, --code)
bx create --type card --name "Visa" --cardholder "John Doe" --number 4111…

# An identity (--title, --first-name, --last-name, --email, --ssn, …)
bx create --type identity --name "Passport" --first-name "John" --last-name "Doe"

# An SSH key (--private-key or --private-key-stdin, --public-key, --fingerprint)
bx create --type ssh-key --name "Server" --private-key-stdin < ~/.ssh/id_ed25519
```

The same fields can be edited: `bx edit --type-specific-flag value`, and in
the interactive editor (`bx edit -i`), which shows the item's fields as a
template — including those of cards, identities and SSH keys (a multi-line
private key is stored quoted and survives the round trip).  Flags that do not
apply to the item's type are rejected instead of silently dropped.

**Conflict detection** — `bx edit` and `bx delete` fetch the server's
`RevisionDate` before writing.  If the server copy is newer than the local
cache, the command aborts with a clear message.  Use `--force` to skip the
check, or run `bx fetch` first to pull the latest changes.

**Nothing is lost on edit** — `bx edit` applies your changes to the server's
complete copy of the item and sends everything else back untouched: passkeys,
password history, custom fields, URI match settings, re-prompt, and fields bx
does not know about.  A changed password is added to the item's password
history, as the official clients do.

### Sharing items with an organization

Items you create belong to you.  To share one — the Bitwarden equivalent of
changing an item's *owner* to an organization and picking its collections — pass
`--organization` and one or more `--collection` flags to `bx edit`:

```bash
# See which organizations and collections you have access to
bx collection list
bx collection list --organization "Family"

# Change the owner of an item to the "Family" organization and share it with
# the "Wife" and "Kid 1" collections
bx edit "Disney+" --organization "Family" --collection "Wife" --collection "Kid 1"

# Change only the collections of an item that already belongs to an organization
# (--collection replaces the current set)
bx edit "Disney+" --collection "Wife"

# bx get shows the owning organization and its collections
bx get "Disney+" --print
```

Organizations and collections can be given by name (case-insensitive), by full
UUID, or by short ID as printed by `bx collection list`.

Moving an item transfers ownership and therefore re-encrypts it with the
organization's key, so every member of the selected collections can read it.
Custom fields, passkeys, TOTP seeds, and password history are re-encrypted along
with it.  A few limits apply, because the Bitwarden API cannot express them:

- `--organization` and `--collection` cannot be combined with field edits
  (`--password`, `--name`, …) in one call — change the owner first, then edit.
- Items with **attachments** can only be moved when they have a per-item key
  (only the wrapped key is re-encrypted, and the attachments stay valid); items
  encrypted with the account key directly are refused, because the API cannot
  re-encrypt their attachment keys.
- An item cannot be moved **back to personal ownership**, nor from one
  organization to another.

## Installation

**Prerequisites:** [Go](https://go.dev/doc/install) 1.26.10+ and `gcc` (CGO is required).

```bash
git clone https://github.com/nning/bx.git
cd bx
make install        # builds and installs to ~/.local/bin/
```

Or just build without installing — the binary will be at `cmd/bx/bx`:

```bash
make build
```

### Shell Completions

```zsh
bx completion zsh > "${fpath[1]}"/_bx
```

Completions are dynamic: item and folder names are completed from the cached
vault when a session is unlocked (nothing is completed — and no password
prompted — when it is locked).

## Features

- **Fast** — minimal startup time, local vault decryption, no unnecessary round-trips
- **Secure by design** — full Bitwarden crypto stack: PBKDF2/Argon2id · AES-256-CBC · HMAC-SHA256
- **2FA support** — TOTP-based two-factor authentication at login
- **Offline access** — encrypted vault cached locally at `~/.bx_vault.json`
- **Unlock timeout** — vault stays unlocked for 15 minutes (configurable) so you only type your password once per session, like `sudo`
- **TOTP generation** — generate codes for vault items with `--totp`
- **Clipboard** — copy secrets directly with `--copy`, or custom field values with `--field`/`-k`
- **Search** — substring, ID, and URL matching across all vault items
- **All item types** — logins, secure notes, cards, identities and SSH keys, including attachments
- **Scripting** — JSON output (`--json`), password-only output (`-P`), dynamic shell completion
- **Generators** — secure random passwords (`bx gen`) and passphrases from the EFF wordlist (`bx gen --words 5`)

The passphrase wordlist is the [EFF Diceware list](https://www.eff.org/dice),
distributed by the Electronic Frontier Foundation under the Creative Commons
Attribution 3.0 license.

## Security

Your master password is **never stored**. It is used only in memory to derive the decryption key. The local vault cache (`~/.bx_vault.json`) contains the same server-encrypted data — decryption happens entirely on your machine.

The optional session cache uses the **OS keyring** (macOS Keychain, GNOME Keyring / KWallet on Linux, Windows Credential Manager) to store the derived account key. The session file `~/.bx_session.json` contains only a timestamp — no key material. Copying the vault file and the session file to another machine is insufficient to decrypt anything; the OS keyring entry is required. Use `bx lock` to clear the session immediately.

On systems without a keyring daemon (e.g., headless servers), the session caching is silently skipped and the master password is requested on every invocation.

The session and refresh tokens, which let their holder sync (but not decrypt) the vault, are kept in the **OS keyring** as well; only on systems without one do they fall back to `~/.bx.yaml` (mode `0600`). The server URL must use `https://`; plain `http://` is only accepted on loopback. This is enforced for existing configurations too. Redirects to another origin are refused. Named accounts do not inherit credentials from the legacy single-account configuration.

When `bx get` writes to a pipe instead of a terminal, it prints the full record, password included, so that it can be used in scripts — mind where you pipe it. Copied secrets are cleared from the clipboard after 30 seconds, but clipboard history managers may keep their own copy.

For the full cryptographic specification, see [SECURITY.md](./SECURITY.md).

## Unlock Timeout

Like `sudo`, `bx` keeps the vault unlocked for a configurable period after a successful password entry so you don't have to retype it for every command:

```bash
bx get "GitHub"         # prompts for master password; vault unlocked for 15 min
bx get "Google"         # no password prompt – session still active
bx lock                 # explicitly lock the vault before the timeout expires
```

The default timeout is **15 minutes**. Configure it with:

```bash
bx config set unlock_timeout 30   # keep unlocked for 30 minutes
bx config set unlock_timeout 0    # disable session caching (always prompt)
```

## Development

```
internal/
  cmd/      CLI commands (Cobra)
  client/   Bitwarden API client
  crypto/   Key derivation, AES decryption, HMAC
  vault/    Local vault loading and decryption
```

```bash
make test    # run tests
make lint    # run linter
make ci      # vet + test + build
```

## Roadmap

See [ROADMAP.md](./ROADMAP.md) for planned features and [CHANGELOG.md](./CHANGELOG.md) for what changed.

## License

MIT

## Releases and license

Releases are triggered manually with a semantic version tag. The workflow
validates the tagged commit, tests it, checks for known vulnerabilities, and
builds both platforms from that same commit. Build metadata does not contain
local paths or earlier Git history.

bx is distributed under the [MIT license](LICENSE). The embedded EFF wordlist
has its own attribution license; see [third-party notices](THIRD_PARTY_NOTICES.md).

The CI also tests attachment transfers against a disposable Vaultwarden server.
To run this check locally, start a disposable server with registration enabled
and set `BX_TEST_VAULTWARDEN_URL=http://127.0.0.1:<port>` when running
`go test ./internal/client -run TestVaultwardenAttachmentIntegration -v`.
The check creates a synthetic account and must never target a personal server.
