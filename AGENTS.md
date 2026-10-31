# Agent Instructions for bx

`bx` is a high-performance CLI client for Bitwarden/Vaultwarden written in Go. It focuses on speed and maintainability with a strong emphasis on cryptographic security.

## Multi-Agent Collaboration

You are working in parallel with other agents on the same git repo. Follow these practices:
- Create sensible-sized, logically cohesive commits (one feature or fix per commit)
- Always pull before pushing to catch changes from parallel work
- Push regularly to avoid long-lived branches and reduce merge conflicts
- Write clear commit messages using [Conventional Commits](https://www.conventionalcommits.org/) specification:
  - Format: `<type>(<scope>): <description>` (e.g., `feat(crypto): add Argon2id support`)
  - Types: `feat`, `fix`, `docs`, `style`, `refactor`, `perf`, `test`, `chore`
  - Include the co-author trailer: `Co-authored-by: Copilot <223556219+Copilot@users.noreply.github.com>`

## Build, Test, and Lint Commands

### Building
```bash
make build           # Build the binary (output: cmd/bx/bx)
make install         # Build and install to ~/.local/bin/
```

Build uses Go 1.26.10+ and requires `CGO_ENABLED=1`. The version is injected via ldflags; build paths and VCS build metadata are omitted.

### Testing
```bash
make test            # Run all tests with coverage (generates .coverage)
go test ./internal/crypto -v   # Run a specific package's tests
go test -run TestName ./...    # Run a specific test by name
make coverage        # Generate and open HTML coverage report
```

Key test files exist for:
- `internal/crypto`: KDF, AES encryption, HKDF expansion
- `internal/client`: API type handling and responses
- `internal/vault`: Vault loading and decryption

### Linting & Verification
```bash
make lint            # Run golangci-lint (uses the pinned tool version)
make vet             # Run go vet
make ci              # Run the full CI pipeline: clean, vet, test, lint, vulnerability scan, build
```

Linting uses golangci-lint v2 with `.golangci.yml`: the standard linter set (errcheck, govet, ineffassign, staticcheck, unused) plus the gofmt and goimports formatters, so unformatted code fails `make lint` and the CI lint job.

### Development
```bash
make clean           # Remove build artifacts
```

## High-Level Architecture

### Package Structure
- **`cmd/bx/main.go`** - Entry point that delegates to `internal/cmd.Execute()`
- **`internal/cmd/`** - CLI command definitions using Cobra (setup, account, login, fetch, list, get, create, edit, delete, restore, folder, collection, gen, lock, config)
- **`internal/client/`** - API communication and type definitions for Bitwarden API
- **`internal/crypto/`** - Cryptographic primitives implementing Bitwarden's security spec
  - KDF (PBKDF2 and Argon2id support)
  - AES-256-CBC encryption
  - HKDF for master key expansion
  - HMAC-SHA256 for authentication
- **`internal/vault/`** - Local vault management (loading, caching, decryption of `~/.bx_vault.json`)

### Data Flow
1. **Login**: Master password → KDF → Master key → master password hash → OAuth2 session and refresh tokens, stored in the OS keyring (fallback: `~/.bx.yaml`)
2. **Fetch**: Download encrypted vault → store at `~/.bx_vault.json` (unmodified from server)
3. **Access**: Load vault → decrypt items using locally-derived keys (no server interaction); the derived account key is cached in the OS keyring for `unlock_timeout` minutes
4. **Write**: `create`/`edit`/`delete`/`restore` call the API, then patch the local vault cache

### Security Model
- Master password never stored, only used for key derivation in memory
- Vault decryption happens entirely locally after sync
- All crypto follows Bitwarden's official specification (PBKDF2/Argon2id, AES-256-CBC, HMAC)
- See `SECURITY.md` for detailed cryptographic specifications

## Key Conventions

### Configuration & State
- Config: `~/.bx.yaml` (accounts, server URL, email, device ID; written atomically via `saveConfig`)
- Tokens and session keys: OS keyring (service `bx`), see `internal/cmd/tokens.go` and `internal/vault/session.go`
- Cache: `~/.bx_vault.json` (encrypted vault backup), per account `~/.bx_vault_<name>.json`
- Config is managed with Viper

### Command Pattern
Each command in `internal/cmd/` follows a consistent pattern:
- Uses `apiClient` (initialized from root command) for API calls
- Loads config via `viper.GetString()`, `viper.GetString()`, etc.
- Returns error codes via `os.Exit()` on failure

### Cryptographic Functions
- `internal/crypto/kdf.go`:
  - `DeriveMasterKey(password, email, iterations, algorithm)` → 32-byte master key
  - `HashMasterPassword(masterKey)` → Auth hash for OAuth2
  - PBKDF2 and Argon2id support via algorithm parameter
- `internal/crypto/aes.go`:
  - `Decrypt(ciphertext, key, iv, mac)` → plaintext with HMAC verification

### Error Handling
- Cobra commands print errors via `fmt.Println(err)` in the root command
- Network errors and crypto failures are not silenced; propagate to user
- See test files for error case examples

### Testing Patterns
- Crypto functions have explicit test vectors (see `*_test.go` files)
- Tests use `testing.T` with standard patterns
- No test helpers or assertion libraries (plain Go testing)

### Dependencies
- **Cobra** - CLI framework
- **Viper** - Config management
- **crypto/aes, crypto/hmac, crypto/sha256** - Standard library crypto (no external crypto libs)
- **pquerna/otp** - TOTP generation
- **atotto/clipboard** - Clipboard operations
- **barcode** - For TOTP QR code support (transitive)
