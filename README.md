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

## Single-item precondition

`Set` writes with `add-generic-password -U -s <service> -a <account>` and
verifies with `find-generic-password -s <service> -a <account>`. `-U`
updates the item matching that attribute set; `find` returns the first
service+account match in keychain search order. Both target the *same*
item only if exactly one exists.

**This is a hard precondition, not a caveat.** If a duplicate (service,
account) item exists — planted by another tool with extra attributes, or
living in a different keychain (system vs. login) — write and read-back
can silently address *different* items:

- Get can return the OTHER item's value: stale, or attacker-controlled if
  the higher-priority keychain isn't yours to trust.
- Set's read-back can verify against the other item too, masking a write
  that landed on the wrong one — a correct write followed by a read of the
  other item produces a spurious `ErrVerifyFailed`, or (if the values
  happen to match) a masked no-op.

A caller MUST do one of the two:

1. **Pin a keychain** with `keyring.New(service, keyring.WithKeychain(path))`
   — every find/add call scopes to that one keychain file, closing the
   ambiguity outright. `path` must be absolute.
2. **Guarantee uniqueness** — exactly one (service, account) item across the
   whole default keychain search path, for the life of the Store.

This library assumes it is the only writer for its service namespace. If
`ErrVerifyFailed` fires on what looks like a correct write and you have not
pinned a keychain, check for a duplicate item first
(`security dump-keychain | grep <service>` across keychains) — the fix is
pinning a keychain, deleting the duplicate, or picking a distinct service
name, not retrying the write.

## Test kill-switch

`KEYRING_DISABLE=1` (any non-empty value) makes every operation return
`ErrUnsupported` and `Supported()` report false — the Store behaves exactly
like a build with no backend, and `GetOrEnv` falls through to the
environment. It exists for test harnesses that exec a **built** consumer
binary (blackbox/txtar suites), where `WithSecurityBin` cannot be injected:
set it in the subprocess env and the developer's real keychain can never
leak into an env-isolated test. Read at call time, so in-process tests can
toggle it with `t.Setenv(keyring.DisableEnv, "1")`.

## Consuming this module (it is private)

`github.com/dkoosis/keyring` is a private repo. Builds that fetch it need:

```sh
export GOPRIVATE='github.com/dkoosis/*'
# plus a github.com git credential (gh auth login covers local dev)
```

CI (GitHub Actions) — the default `GITHUB_TOKEN` cannot read another
private repo. Add a fine-grained PAT (read-only Contents on this repo) as a
repo secret, e.g. `DKOOSIS_MODULES_TOKEN`, then before any Go step:

```yaml
- run: git config --global url."https://x-access-token:${{ secrets.DKOOSIS_MODULES_TOKEN }}@github.com/".insteadOf "https://github.com/"
  env: {}
- run: echo 'GOPRIVATE=github.com/dkoosis/*' >> "$GITHUB_ENV"
```

Docker builds need the same via a build secret — never bake the token into
a layer.

## Testing

`go test ./...` runs stub-based contract tests (argv shape, stdin protocol,
error classification, timeouts) on any OS. The live end-to-end test against
the real keychain is opt-in — `KEYRING_LIVE_E2E=1 go test -run
TestLiveKeychain` in an interactive terminal (`security`(1) prompts on
`/dev/tty`, so it cannot run headless). CI runs contract tests only; a
manual live check on a real Mac gates each release.
