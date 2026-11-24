# auth

A local YubiKey authenticator for Debian 13 / compatible Ubuntu. No daemon,
root, configuration file or persistent secret cache. Requires system Python 3,
`ykman` and its matching Python SDK (ykman/yubikit, normally installed together
by the distribution). The executable uses /usr/bin/python3 to find system packages.

## Install

From the repository root, run `sudo apt install yubikey-manager` (installs
host packages), then `install -Dm755 bin/auth ~/.local/bin/auth` (copies one
executable). Ensure ~/.local/bin is on PATH. Uninstall with
`rm ~/.local/bin/auth`. No YubiKey changes occur during installation.

## Commands

| Invocation | Effect |
| --- | --- |
| auth | Watch TOTP codes until interrupted; non-TTY prints one snapshot |
| auth QUERY | Select one unique substring match; explicit touch account gives one code |
| auth list / ls | Read visible OATH account names and types |
| auth add [issuer:name] | Persistent enrollment, default no touch, six digits, SHA1, 30s |
| auth rename QUERY NAME | Persistent rename, preserves issuer unless specified |
| auth rm QUERY / remove QUERY | Irreversible deletion, default No |
| auth fido | Native discoverable credential list, secure backend PIN prompt |
| auth pgp | Read native OpenPGP info and available slot metadata |
| auth doctor | Read-only policy matrix for each connected serial-numbered USB key |
| auth help / --help / --version | Help/version |

Global --device SERIAL selects one detected key. More than one key requires
selection for all commands except doctor. Add accepts --algorithm, --digits,
--period, --oath-type and --counter. Writes require a terminal and confirmation.
No secret or PIN in argv. OATH password is prompted once per session and not
cached by the wrapper. HOTP is deliberately not generated, even for a query;
use raw ykman deliberately if needed. Hidden accounts are omitted from views.

Exit codes: 0 success, 1 doctor policy mismatch, 2 dependency/usage/backend
failure or unverified device policy, 130 interrupt (SIGINT or SIGTERM).
Unknown clock status alone is informational; a negative clock sync report is
a mismatch. Clock sync does not establish actual clock accuracy.

## Implementation choices and limitations

- Uses the official Yubico Python SDK for OATH, rather than the CLI code command.
  In upstream 5.6.1, that command automatically calculates a lone matching HOTP
  and can delete a corrupted credential on memory failure. The SDK calculate_all
  explicitly excludes HOTP and touch, does not invoke CLI repair, and provides
  actual validity intervals. SDK exact byte IDs also avoid fuzzy write races.
  The upstream 5.6.1 source was inspected; installed backend help and actual
  Debian/Ubuntu compatibility still require validation.
- The 5.6.1 CLI add prompt does not hide the entered Base32 secret. The wrapper
  therefore uses getpass and the SDK instead; no touch enrollment or forced
  overwrite. No cryptographic algorithms are reimplemented.
- FIDO uses the native table rather than CSV parsing to preserve the backend
  prompt. Wrong PIN can reduce retries; no automatic retry. Discoverable
  credentials are not a complete registration inventory.
- OpenPGP prints backend metadata; unknown/inaccessible slots remain unknown.
  Doctor does not authenticate, install, repair, or change any setting.
- Live view updates only its own lines; terminal size/account count changes
  stop the view rather than risk overwriting shell history. Disconnect is
  detected on the next hardware refresh, then the command exits; rerun after
  reconnecting. Accounts requiring touch are not polled automatically.
  Touch-required Steam accounts are not supported.
- No live hardware, installed ykman, or runtime dependency verification was
  available during authoring. This is a review candidate, not production-ready.

## Verify

Run `python3 -m unittest discover -s tests -p test_auth.py -v`.
Fixtures contain invented names and codes; tests never use hardware.

Optional hardware checks, separately for each key:
1. `ykman --version`, `ykman oath accounts list --help`, `ykman oath accounts
   code --help`, `ykman openpgp keys info --help`, `auth doctor`.
2. Compare `auth list` with native list; watch across a real period boundary,
   Ctrl+C, resize, disconnect, multiple devices and redirected output. Test
   HOTP-only and touch-only cases without advancing HOTP.
3. Run `auth fido` with the correct PIN (wrong PIN reduces retry counter);
   compare `auth pgp` against native slot metadata.
4. Only with a disposable test secret and explicit permission: add an account
   (persistent; remove to undo), rename it (persistent; rename back to undo),
   then remove it (irreversible without the original secret). Verify by listing
   after each operation. Do not test on production credentials.

References: [Yubico CLI guide](https://docs.yubico.com/software/yubikey/tools/ykman/),
[OATH CLI 5.6.1 source](https://github.com/Yubico/yubikey-manager/blob/5.6.1/ykman/_cli/oath.py),
[OATH SDK 5.6.1 source](https://github.com/Yubico/yubikey-manager/blob/5.6.1/yubikit/oath.py).
