# Security Specification & Audit Guide

This document provides a detailed technical overview of the security architecture and cryptographic implementation of `bx`. It is intended for security audits and for users who want to understand how their sensitive data is handled.

## 1. Threat Model

`bx` is designed to protect your Bitwarden/Vaultwarden credentials against:
- **Server-side compromises:** Data is stored encrypted; the server never sees your master password or the keys required to decrypt your vault.
- **Network interception:** All communication is performed over HTTPS, and sensitive payloads are cryptographically protected. `bx setup` and `bx account add` refuse a server URL that is not `https://`, except plain `http://` to a loopback address (a local Vaultwarden).
- **Local theft of the vault cache:** The local vault (`~/.bx_vault.json`) is stored in its encrypted form, exactly as it is received from the server.

`bx` assumes the following are secure:
- The local machine's memory and file system permissions (standard user-level isolation).
- The integrity of the Go compiler and the standard library.

## 2. Key Derivation Flow

`bx` strictly follows the Bitwarden cryptographic specification for key derivation.

### 2.1. Master Key Derivation
When you log in or access the vault, your **Master Password** and **Email** are used to derive a **Master Key**.

- **Input:** Master Password, Email (as salt).
- **KDF Algorithms Supported:**
  - **PBKDF2-SHA256:** Uses the iteration count provided by the server (default is 600,000). Salt = raw email (lowercased).
  - **Argon2id:** Uses the memory, parallelism, and iteration parameters provided by the server. Salt = SHA256(email lowercased), yielding a fixed-length 32-byte value per the Bitwarden specification.
- **Output:** A 32-byte (256-bit) **Master Key**.

*Implementation: `internal/crypto/kdf.go:DeriveMasterKey`*

### 2.2. Master Password Hash (Authentication)
To authenticate with the server without sending the Master Password, `bx` derives a separate hash.

- **Algorithm:** PBKDF2-SHA256.
- **Input:** Master Key.
- **Salt:** Master Password.
- **Iterations:** 1.
- **Output:** A Base64-encoded string sent to the server as the `password` field in the OAuth2 flow.

*Implementation: `internal/crypto/kdf.go:HashMasterPassword`*

## 3. Vault Decryption Architecture

### 3.1. Master Key Expansion (HKDF)
Before the Master Key can be used to decrypt the account's symmetric key, it is expanded into two separate keys: one for encryption and one for integrity (MAC).

- **Algorithm:** HKDF-SHA256.
- **Expansion 1 (enc):** Info = `enc`, Output = 32 bytes.
- **Expansion 2 (mac):** Info = `mac`, Output = 32 bytes.
- **Total:** A 64-byte expanded key.

*Implementation: `internal/crypto/aes.go:ExpandKey`*

### 3.2. Account Key Decryption
The **User Symmetric Key** (Account Key) is stored on the server (and in the local cache) as a "protected" cipher string.

- **Cipher Type:** Type 2 (AesCbc256_HmacSha256_B64).
- **Key:** The 64-byte expanded Master Key.
- **Process:**
  1. Verify the HMAC-SHA256 of the ciphertext using the `mac` portion of the key.
  2. Decrypt the ciphertext using AES-256-CBC with the `enc` portion of the key and the provided IV.
  3. The result is the **Account Key**, which is used to decrypt all items in the vault.

*Implementation: `internal/vault/vault.go:LoadVault`*

### 3.3. Item Decryption
Vault items (ciphers) like passwords and notes are decrypted using the Account Key.

- **Algorithm:** AES-256-CBC + HMAC-SHA256.
- **Integrity:** HMAC-SHA256 is verified before decryption to prevent padding oracle attacks and ensure data integrity.
- **Padding:** PKCS7.
- **Type 0 (AesCbc256_B64, no MAC):** Only accepted under a legacy 32-byte key. Every key `bx` holds is a 64-byte enc+mac key, so a type 0 value is refused; otherwise anyone who can modify the vault cache could strip the MAC from a type 2 value and tamper with the ciphertext undetected.

*Implementation: `internal/crypto/aes.go:Decrypt`, `decryptType2`*

## 4. Data Persistence

### 4.1. Sensitive Data (Encrypted)
- **`~/.bx_vault.json`**: Contains the full vault sync response. All sensitive fields (names, passwords, notes, TOTP secrets) are **encrypted cipher strings**. This file is created with `0600` (read/write for owner only) permissions.

### 4.2. Configuration and Tokens
- **`~/.bx.yaml`**: Stores metadata such as the server URL, email, device ID and the encrypted `protected_key`. It is written with **`0600` permissions** (read/write for owner only) through a temp file and an atomic rename, so an interrupted write never truncates it and a symlink planted at its path cannot redirect the write.
- **OAuth2 tokens:** The session (access) token and the refresh token let their holder sync the vault from the server (though not decrypt it). They are stored in the **OS keyring** (service `bx`, user `tokens` or `tokens_<account>`), alongside the session keys. Tokens an older `bx` left in `~/.bx.yaml` are moved to the keyring on the next run.
- **Fallback:** On systems without a keyring daemon (e.g. headless servers) the tokens fall back to `~/.bx.yaml`, protected only by its `0600` permissions. If that file is compromised, log out of the device in the web vault to revoke the tokens.

## 5. Security Best Practices Implemented

- **No Password Storage:** The Master Password is never stored on disk. It is held in memory only for the duration of the command execution.
- **Secure File Permissions:** All local storage files (`.bx_vault.json`, `.bx.yaml`, session timestamps) are created with `0600` permissions and replaced atomically through a temp file and rename, preventing TOCTOU races.
- **Key Material Wiping:** The master key, the stretched master key, the RSA private key and unexpanded item keys are overwritten with zeros as soon as they are no longer needed. This is best-effort: Go's garbage collector may have copied them.
- **Secrets Kept out of argv:** `--password-stdin` reads an item password from a pipe. `bx create`/`bx edit` warn when `--password` or `--totp` is passed on the command line, where `ps` and the shell history can see it. A password generated with `--generate` is copied to the clipboard instead of being printed.
- **Secure Input:** Passwords are read using `golang.org/x/term`, which disables terminal echo.
- **Surgical Decryption:** `bx` only decrypts the specific fields requested (e.g., during `bx get`), minimizing the exposure of decrypted data in memory.
- **Standard Library Primitives:** All cryptographic operations use Go's `crypto/` package for timing-attack resistance and audited implementations.
- **Clipboard Auto-Clear:** Passwords and TOTP codes are automatically cleared from the clipboard after 30 seconds (configurable) to reduce the exposure window. The detached helper receives only the SHA-256 of the secret, on stdin, and clears the clipboard only if it still holds that secret, so it neither wipes something copied in the meantime nor can be used by other processes to clear the clipboard. Clipboard history managers keep their own copy, which `bx` cannot clear; it says so when copying.
- **Editor Temp Files:** `bx edit -i` writes the decrypted item to a private `0700` directory under `$XDG_RUNTIME_DIR` (a per-user tmpfs on Linux) when available, and overwrites it before removal. Overwriting is best-effort on SSDs and copy-on-write file systems.
- **Length Limits:** Encrypted values are checked against the Bitwarden server's limits (e.g. 10,000 characters for notes) before a request is sent.
- **TLS/HTTPS:** All API communication uses TLS 1.2+ with strong cipher suites to prevent man-in-the-middle attacks. Server URLs must be `https://` (loopback `http://` excepted).
- **Error Message Sanitization:** Server response bodies included in error messages are truncated to 200 characters, so stack traces or other server internals are not dumped to the terminal.
- **Input Validation:** Server URLs, TOTP codes (6–8 digits), and otpauth URIs are validated before processing.
- **KDF Parameter Validation:** `DeriveMasterKey` validates all server-supplied KDF parameters before use. PBKDF2 iterations must be ≥ 1; Argon2id time must be ≥ 1, memory ≥ 1 MB, and parallelism in [1, 255]. This prevents a malicious or compromised server from supplying parameters that cause a panic (e.g., zero iterations or zero parallelism) or force trivially-weak key derivation. It also guards against the silent uint8 wrap-around of the parallelism field (256 → 0).
- **HTTP Client Timeout:** All outbound HTTP requests have a 30-second deadline so that a slow or unresponsive server cannot hang the CLI indefinitely.
- **Response Body Size Limit:** All server response bodies are capped at 100 MiB via `io.LimitReader`, preventing memory exhaustion from a server that streams an unexpectedly large payload.
- **Atomic Vault Write:** The vault cache file (`~/.bx_vault.json`) is always written via a temporary file followed by an atomic rename, ensuring the file is never left in a partial or empty state if the process is interrupted during a write.
- **Symlink-safe Config Write:** `saveConfig` refuses to write when the config path is a symlink or not a regular file, and writes through a fresh temp file that is renamed over the config. A rename replaces the path itself instead of following it, so a symlink planted after the check cannot redirect the write either.

## 6. External Dependencies

`bx` minimizes dependencies to reduce the attack surface. Key dependencies include:
- `golang.org/x/crypto`: For Argon2, PBKDF2, and HKDF.
- `golang.org/x/term`: For secure password prompts.
- `github.com/spf13/cobra/viper`: For CLI and config management.
- `github.com/atotto/clipboard`: For clipboard integration (optional use via `-c`).
- `github.com/pquerna/otp`: For TOTP generation.

## 7. Audit Strategy

To audit the cryptographic correctness of `bx`:
1. Verify `internal/crypto/kdf.go` against the [Bitwarden KDF documentation](https://bitwarden.com/help/cryptography/#key-derivation-and-hashing).
2. Verify `internal/crypto/aes.go` for correct HMAC-then-Decrypt implementation.
3. Review `internal/vault/vault.go` to ensure the Account Key is correctly derived and not leaked.

## Protocol and release checks

All outgoing API requests enforce HTTPS, with an HTTP exception for loopback.
Cross-origin redirects are refused. Signed attachment download and blob URLs
receive no vault Authorization header; direct uploads are restricted to the
configured server origin. Named accounts never inherit legacy account tokens.

Type-2 attachment files use `0x02 || IV (16 bytes) || MAC (32 bytes) || ciphertext`.
RSA-OAEP SHA256 uses type 3; RSA-OAEP SHA1 uses type 4. Other RSA types are rejected.
Decryption failures for supplied organization keys are surfaced as errors.

Attachment output is staged in a 0600 file and published atomically. Replacing
an existing path replaces its directory entry rather than following a symlink
or writing to a hard-linked inode. Temporary and destination directories must
be trusted. Editors, clipboard managers and same-user processes can retain
plaintext outside bx's control.

Use a patched Go toolchain and run `make ci` before releasing. Known-vulnerability
checks and unit tests cannot prove the absence of vulnerabilities. Real-server
integration tests require an isolated test vault; never use personal vault data.
