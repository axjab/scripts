# auth

Go implementation of the local YubiKey authenticator for Debian 13 / compatible
Linux. The previous Python implementation is preserved verbatim as
`bin/auth.py` (and its tests are retained). The Go executable does not call it
or import the Yubico Python SDK. It uses native PC/SC for OATH and the existing
`ykman` CLI for read-only device, FIDO and OpenPGP information.

## Build and install

From the repository root:

~~~sh
sudo apt install golang-go build-essential pkg-config libpcsclite-dev pcscd yubikey-manager
./do/build-auth
install -Dm755 bin/auth ~/.local/bin/auth
~~~

The build installs no packages itself; the first command changes host packages,
not the YubiKey. The Go module lives in cmd/auth, and its dependencies are
version-pinned. The build uses CGO and links the system PC/SC library; it is not
a fully static binary. Target systems need PC/SC runtime, CCID access and ykman.
Cross-compile for the target OS/architecture with a suitable C toolchain.
The generated binary is intentionally not committed. Remove
`~/.local/bin/auth` to uninstall.

## Commands

| Command | Behavior |
| --- | --- |
| auth | Watch TOTP, one global countdown, no terminal clear |
| auth QUERY | Watch one matching TOTP; explicit touch is a one-shot |
| auth list / ls | OATH names/types, no code generation |
| auth add [issuer:name] | Persistent enrollment; no touch, SHA1/6 digits/30s defaults |
| auth rename QUERY NAME | Persistent exact-ID rename, retains issuer/period |
| auth rm QUERY / remove QUERY | Irreversible deletion, confirmation defaults to No |
| auth fido | Native discoverable FIDO2 inventory; PIN prompt |
| auth pgp | Native general and slot metadata |
| auth doctor | Read-only device/clock/application policy report |
| auth --help / help / --version | Help and version |

Use options before the command, e.g. `auth --device SERIAL list` or
`auth --digits 8 add Example`. Enrollment also accepts --algorithm,
--period, --oath-type and --counter. Multiple keys require explicit serial
selection except doctor; the card's serial is verified on the same connection
before OATH access. Doctor inspects all detected serial-numbered keys.

Illustrative output (fictional):

~~~text
ACCOUNT                          CODE
Example                          012345
Other                            573891
Expires in 18s
~~~

All standard 30-second TOTP accounts share the Unix-time boundary. For
nonstandard periods, the same single countdown reports the next expiration,
and nonstandard entries are labeled with their period. Non-TTY stdout prints
one snapshot and exits. HOTP is never calculated by this tool. Steam-format
credentials are not supported in the native Go backend; the preserved Python
implementation or Yubico Authenticator can be used deliberately. An explicit touch-required query is a one-shot. Resize, disconnect, or hardware error
requires restarting watch.

## Code map for a Go beginner

- main.go: argument parsing, cancellation, command routing, secure prompts,
  account matching, confirmation and watch rendering.
- oath.go: PC/SC transport, serial verification, OATH protocol request/response
  parsing, list/calculation/CRUD and password challenge-response. Comments
  explain interfaces, error handling, and the reasons behind safety checks.
- doctor.go: policy comparison and native OpenPGP/FIDO-related diagnostics.
- auth_test.go: hardware-free tests using a fake card and pure functions.
- go.mod: pinned build dependencies.

## Safety and limitations

No OTP, password or Base32 secret is stored on disk, passed as a process
argument or sent to a logging system. The YubiKey performs OTP calculations.
The OATH protocol uses native PC/SC with standard Go crypto libraries for the
documented authentication handshake; no FIDO/OpenPGP algorithms are implemented.
The upstream ykman accounts code command can advance HOTP when a single
account matches and can attempt automatic repair/deletion on corruption.
We never call that command. The card transport uses exact IDs and an exclusive
PC/SC transaction to prevent interleaving with other clients between check and
write. Watch holds that transaction until exit, so other CCID consumers may
wait; stop watch before using those consumers. No driver or daemon is
automatically modified or restarted. SIGINT/SIGTERM cancels watch, but a native
in-flight card operation may complete first. Read-only FIDO inventory may
consume a PIN attempt on incorrect PIN; never automatically retries.

Exit 0 success, 1 verified doctor policy mismatch, 2 usage/backend failure or
unverifiable policy, 130 interrupt. Clock unknown is informational.

## Tests and review

~~~sh
cd cmd/auth
go mod tidy
gofmt -w *.go
go test ./...
go vet ./...
~~~

Run original Python tests from the repo root:
`python3 -m unittest discover -s tests -p test_auth.py -v`.

No attached physical key or installed ykman is available during authoring.
Dependency resolution, Go compilation, tests, and actual card protocol behavior
remain unverified until run on an appropriate host. Do not merge as production
ready before those gates pass. Review native PC/SC code against Yubico's
protocol and test hardware with expendable credentials first. Test each key
independently.

1. Read-only: verify ykman version/help, auth doctor, auth list, multi-key
   selection, FIDO inventory, OpenPGP slots, 30-second and custom TOTP
   boundaries, watch resize/interrupt, non-TTY snapshot, disconnection,
   protected OATH, HOTP-only and touch-only cases. No HOTP calculation.
2. With explicit permission and a disposable secret: add (persistent;
   removable), rename (persistent; rename back), remove (irreversible without
   original secret). Verify by listing after every operation.
3. Never use production credentials for write testing.

References: [Yubico OATH protocol](https://developers.yubico.com/OATH/YKOATH_Protocol.html),
[Yubico SDK source](https://github.com/Yubico/yubikey-manager/blob/5.6.1/yubikit/oath.py),
[management SDK](https://github.com/Yubico/yubikey-manager/blob/5.6.1/yubikit/management.py),
[ykman guide](https://docs.yubico.com/software/yubikey/tools/ykman/).
