#!/bin/sh
# pass2bx — migrate a single pass(1) entry into Vaultwarden via bx.
#
# The decrypted entry never leaves this script: the password is piped into
# `bx create --password-stdin`, so it appears neither in argv (`ps`) nor in the
# shell history. Only bx's own "Created: ..." line is printed.
#
# Usage: pass2bx.sh <pass-path> [-n name] [-u url] [-f folder] [--dry-run]
#
# Defaults: name and url are derived from the last path segment
#           (accounts/example.com -> name "example.com", url "https://example.com").
#
# Metadata lines are read from the entry itself:
#   login:/username:/user:/email:  -> --username
#   url:/site:                     -> --url (overrides the derived one)
# An otpauth:// line is reported but NOT migrated — passing a TOTP seed on the
# command line would expose it in the process list. Add those by hand.

set -eu

usage() {
	echo "usage: $0 <pass-path> [-n name] [-u url] [-f folder] [--dry-run]" >&2
	exit 2
}

[ $# -ge 1 ] || usage
src=$1
shift

name=""
url=""
folder=""
dry_run=0

while [ $# -gt 0 ]; do
	case $1 in
	-n) name=${2:?}; shift 2 ;;
	-u) url=${2:?}; shift 2 ;;
	-f) folder=${2:?}; shift 2 ;;
	--dry-run) dry_run=1; shift ;;
	*) usage ;;
	esac
done

leaf=${src##*/}
parent=${src%/*}
parent=${parent##*/}

# is_host reports whether $1 looks like a hostname (optionally with a port).
is_host() {
	printf '%s' "$1" | grep -qE '^[a-z0-9.-]+\.[a-z]{2,}(:[0-9]+)?$'
}

# In a store like www/google.com/ann the leaf is the account and the parent is
# the site, so name both — "ann" alone would be meaningless in the vault.
if is_host "$parent"; then
	host=$parent
	[ -n "$name" ] || name="$parent ($leaf)"
else
	host=$leaf
	[ -n "$name" ] || name=$leaf
fi

# Decrypt once, keep it in a shell variable rather than a temp file.
entry=$(pass show "$src")

password=$(printf '%s\n' "$entry" | head -n 1)
if [ -z "$password" ]; then
	echo "error: $src has an empty first line (no password)" >&2
	exit 1
fi

meta=$(printf '%s\n' "$entry" | tail -n +2)

field() {
	printf '%s\n' "$meta" |
		sed -n "s/^[[:space:]]*\($1\):[[:space:]]*//Ip" |
		head -n 1
}

username=$(field 'login\|username\|user\|e-\?mail')
[ -n "$url" ] || url=$(field 'url\|site\|website')

# Fall back to the host as a URL only when it looks like one, so that entries
# like "1/misc/yubikey" do not get a bogus URL.
if [ -z "$url" ] && is_host "$host"; then
	url="https://$host"
fi

if printf '%s\n' "$meta" | grep -q 'otpauth://'; then
	echo "note: $src carries a TOTP seed — add it manually, it is not migrated" >&2
fi

set -- --name "$name" --password-stdin
[ -n "$username" ] && set -- "$@" --username "$username"
[ -n "$url" ] && set -- "$@" --url "$url"
[ -n "$folder" ] && set -- "$@" --folder "$folder"

if [ "$dry_run" -eq 1 ]; then
	echo "would run: bx create $* (password from stdin, ${#password} chars)"
	exit 0
fi

printf '%s\n' "$password" | bx create "$@"
