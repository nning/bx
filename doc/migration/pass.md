# Migrate from pass to bx

Use `pass2bx.sh` to migrate one login entry at a time. Configure bx for the
intended account and run `bx fetch`, then unlock it with `bx list`.

```sh
./pass2bx.sh accounts/example.com/alice -n "Example Service" --dry-run
./pass2bx.sh accounts/example.com/alice -n "Example Service"
```

The script reads the first line as the password and pipes it to
`bx create --password-stdin`. It reads username and URL metadata when present.
The dry run prints the proposed item name, username, URL and password length;
it does not print the password. Treat this metadata as private too.

Do not pass passwords or TOTP seeds as command-line arguments. Avoid shell
tracing (`set -x`), logs that capture decrypted output, and plaintext temporary
files. The master password is requested through the terminal. TOTP seeds and
non-login entries require manual migration; the script does not migrate them.

Use `--account` on bx commands to choose the destination account. The script
uses the active account, so select it explicitly before running the script.
Verify the migrated entry before deleting its source. Keep a separate encrypted
backup until all entries have been checked.
