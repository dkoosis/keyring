# keyring

macOS keychain access for Go via the `security` CLI — no cgo, no third-party
dependencies. Built for CLI tools and daemons that need an API key or token
without config-file or env-var plumbing.

```go
store, err := keyring.New("myapp")
if err != nil { ... }

// Keychain-first, env fallback (works headless, works on Linux).
key, err := store.GetOrEnv("anthropic", "MYAPP_ANTHROPIC_API_KEY")
```

## Guarantees

1. **Secrets never touch argv.** Writes pipe the value to
   `security add-generic-password` on stdin, so it can never appear in `ps`
   or a process-table snapshot.
2. **Writes are verified.** A locked keychain can make `security` report
   success while storing nothing; `Set` reads the value back and compares.
3. **Absolute binary path.** `/usr/bin/security` is invoked absolutely — a
   hijacked `$PATH` cannot substitute a malicious binary into the credential
   path.
4. **"Not found" is never conflated with "could not read".** Only
   `security`'s confirmed item-not-found (exit 44) maps to `ErrNotFound`.
   A locked keychain, a denied dialog, or a timeout is `ErrUnreadable` —
   callers using `Has` as an overwrite guard must block on it, because
   treating "couldn't read" as "absent" invites clobbering a value that is
   actually there.
5. **Bounded calls.** Every `security` invocation carries a timeout
   (default 10s, `WithTimeout` to change), so a wedged unlock prompt becomes
   an error instead of a hang.

The not-found/unreadable split is a best-effort classification of the Darwin
`security` CLI (exit status + stderr text). It is reliable on stock macOS,
but it is a CLI heuristic, not an OS guarantee.

## Non-darwin

On non-darwin builds `Supported()` returns false and every keychain
operation returns `ErrUnsupported`. `GetOrEnv` falls through to the
environment there, so one code path serves macOS and Linux. `ErrUnreadable`
never falls through — a locked keychain surfaces as an error rather than
silently downgrading to env.

## Conventions

- **service** = your app's name (`myapp`) — the keychain namespace.
- **account** = the secret's purpose (`anthropic`, `github`).
- **env fallback** = `<APP>_<PROVIDER>_API_KEY` (`MYAPP_ANTHROPIC_API_KEY`).

Store a secret from a terminal (value prompted, off argv):

```sh
security add-generic-password -U -s myapp -a anthropic -w
```

## Testing

`go test ./...` runs stub-based contract tests (argv shape, stdin protocol,
error classification, timeouts) on any OS. The live end-to-end test against
the real keychain is opt-in — `KEYRING_LIVE_E2E=1 go test -run
TestLiveKeychain` in an interactive terminal (`security`(1) prompts on
`/dev/tty`, so it cannot run headless). CI runs contract tests only; a
manual live check on a real Mac gates each release.
