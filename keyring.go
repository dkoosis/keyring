// Package keyring stores and retrieves secrets in the macOS keychain via the
// `security` CLI — no cgo, no third-party dependency. Secrets never appear on
// a process argv, writes are verified by read-back, and "not found" is kept
// strictly distinct from "could not read" so callers get an honest answer to
// "does this exist right now" — but that answer is a point-in-time read, not
// an atomic guard: `security add-generic-password -U` unconditionally
// overwrites on Set, so a concurrent writer between a caller's presence
// check and its Set is clobbered with no error to either side. Has is
// advisory, not a compare-and-swap; this package assumes one writer per
// account. See Has.
//
// PRECONDITION: exactly one (service, account) item across the keychain
// search list, or a pinned keychain. `find-generic-password` returns the
// FIRST match in keychain search order and `add-generic-password -U`
// updates "the" matching item — whichever one that search order picks. A
// duplicate item planted by another tool in a higher-priority keychain
// means Get can return that other item's value (stale or
// attacker-controlled) and Set's read-back can verify against it too,
// masking a write to the wrong item. Callers that cannot guarantee
// uniqueness across the search list MUST pin a keychain with WithKeychain.
// See WithKeychain and the README's "Single-item assumption" section.
//
// Service names, account names, and values must be printable ASCII
// (0x20-0x7e): `security find-generic-password -w` hex-transcribes any
// stored value containing a byte >=0x80 on read, indistinguishable from a
// real value, so Set refuses non-ASCII input up front. Encode non-ASCII or
// multi-line material (e.g. base64) before storing.
//
// On non-darwin builds every keychain operation returns ErrUnsupported;
// GetOrEnv falls through to the environment there, so cross-platform callers
// can use one code path.
package keyring

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Sentinel errors, wrapped with %w — test with errors.Is.
//
// The ErrNotFound / ErrUnreadable split is a best-effort classification of
// the Darwin `security` CLI's behavior (exit status 44, or a "could not be
// found" stderr message). It is reliable on stock macOS but is a CLI
// heuristic, not an OS guarantee: treat ErrNotFound as "confirmed absent on
// this backend", and never treat any OTHER failure as absence.
var (
	// ErrNotFound means the item is CONFIRMED absent from the keychain.
	ErrNotFound = errors.New("not found")
	// ErrUnreadable means the item could not be read for a reason other than
	// confirmed absence — locked keychain, denied access dialog, timeout. It
	// is NOT "absent": a caller using presence as an overwrite guard must
	// block on it, never treat it as "no value, safe to write".
	ErrUnreadable = errors.New("keychain item could not be read")
	// ErrVerifyFailed means the post-Set read-back failed or did not match
	// the stored value. The returned error chains the underlying cause where
	// one exists.
	//
	// INDETERMINATE, not "not written": write and read-back are two separate
	// `security` invocations with no lock or transaction spanning the gap, so
	// this error can fire while the value is durably stored — a concurrent
	// Set to the same account landing in the gap (read-back sees the other
	// writer's value; the keychain state is still consistent, last write
	// wins), or the keychain locking/denying access after the write lands but
	// before the read-back runs. A caller MUST NOT treat ErrVerifyFailed as
	// proof the value is absent, and must not route the secret to a fallback
	// store on this error — doing so risks two sources of truth for the same
	// account. Set deliberately does not auto-rollback (delete the item) on
	// this error either: a transient read failure is indistinguishable from
	// the cases above, and rolling back could destroy a good pre-existing
	// value that Set never touched. Retry Get (or Has) to resolve the
	// uncertainty instead.
	ErrVerifyFailed = errors.New("read-back verification failed")
	// ErrUnsupported means no keychain backend is compiled into this binary
	// (any non-darwin build).
	ErrUnsupported = errors.New("keychain not supported on this platform")
)

// defaultTimeout bounds each `security` invocation. A wedged keychain process
// (e.g. an unlock prompt nobody answers) would otherwise hang the caller
// forever; the timeout turns that into a prompt error instead.
const defaultTimeout = 10 * time.Second

// DisableEnv is the environment kill-switch: when set to any non-empty value,
// every keychain operation returns ErrUnsupported and Supported() reports
// false, exactly as on a platform with no backend — so GetOrEnv falls through
// to the environment. It exists for test harnesses that exec a BUILT consumer
// binary (blackbox/txtar suites), where WithSecurityBin cannot be injected:
// setting KEYRING_DISABLE=1 in the subprocess env guarantees the developer's
// real keychain can never leak into an env-isolated test. It is read at call
// time, not init, so in-process tests can toggle it with t.Setenv.
const DisableEnv = "KEYRING_DISABLE"

// disabled reports whether the DisableEnv kill-switch is set.
func disabled() bool { return os.Getenv(DisableEnv) != "" }

// printableASCIIOnly rejects strings containing anything outside printable
// ASCII (0x20-0x7e). Two reasons collapse into one check: a control
// character (below 0x20, or DEL) would terminate or corrupt the
// `security -i` command line the darwin write path feeds the CLI, and
// `security find-generic-password -w` HEX-TRANSCRIBES any value containing a
// byte >=0x80 on read-back instead of returning the original bytes — with
// exit 0 and no marker distinguishing the transcription from a real value
// (kr-yqk: storing "café" reads back as the literal string "636166c3a9", a
// silently wrong credential, not an error). Rejecting >0x7e up front is the
// only sound fix: Get cannot detect the corruption after the fact. Store
// multi-line or non-ASCII material (PEM keys, secrets with accented/Unicode
// characters) encoded — e.g. base64 — as canapay does for its SFTP seed.
func printableASCIIOnly(what, s string) error {
	for _, r := range s {
		if r < 0x20 || r > 0x7e {
			return fmt.Errorf("keyring: %s must be printable ASCII (got %q); encode non-ASCII or multi-line material (e.g. base64) before storing", what, r)
		}
	}
	return nil
}

// printableASCIIOnlySecret is printableASCIIOnly for secret VALUES: same
// validation, but the error never echoes the offending rune, since that rune
// is a byte of the secret and would otherwise leak into error text and logs.
// Non-secret fields (service name, account) keep the rune in their error via
// printableASCIIOnly — it aids debugging and leaks nothing.
func printableASCIIOnlySecret(what, s string) error {
	for _, r := range s {
		if r < 0x20 || r > 0x7e {
			return fmt.Errorf("keyring: %s must be printable ASCII (0x20-0x7e); encode non-ASCII or multi-line material (e.g. base64) before storing", what)
		}
	}
	return nil
}

// errDisabled is the ErrUnsupported-wrapping error every operation returns
// while the kill-switch is set; it names the env var so an unexpectedly inert
// keychain is diagnosable from the error text alone.
func errDisabled() error {
	return fmt.Errorf("keyring: disabled by %s: %w", DisableEnv, ErrUnsupported)
}

// Store reads and writes secrets under one keychain service name.
type Store struct {
	service     string
	timeout     time.Duration
	securityBin string // absolute path; reassigned only by tests
	keychain    string // absolute path to a pinned keychain file; empty = default search list
}

// Option configures a Store.
type Option func(*Store)

// WithTimeout overrides the per-invocation timeout (default 10s).
func WithTimeout(d time.Duration) Option {
	return func(s *Store) { s.timeout = d }
}

// WithSecurityBin overrides the path to the `security` binary. FOR TESTS
// ONLY — it exists so consumers can point a Store at a stub and assert the
// CLI contract. Production code must keep the default absolute path.
// New rejects a non-absolute path outright: a relative or $PATH-resolved
// override reopens the PATH-hijack hole the default exists to close, and
// whatever binary ends up at that path receives the secret on stdin during
// Set.
func WithSecurityBin(path string) Option {
	return func(s *Store) { s.securityBin = path }
}

// WithKeychain pins every find-generic-password and add-generic-password
// call to one keychain file, instead of `security`'s default search list.
//
// Precondition this closes: find-generic-password returns the FIRST
// service+account match in keychain search order, and add-generic-password
// -U updates "the" matching item — whichever one that search order picks.
// A duplicate (service, account) item planted by another tool in a
// higher-priority keychain (e.g. system ahead of login) means Get can
// return that OTHER item's value — attacker-controlled or merely stale —
// and Set's read-back can verify against it too, masking a write that
// landed on the wrong item entirely. See "Single-item assumption" in the
// package doc and README.
//
// WithKeychain removes the ambiguity by scoping both the read and the write
// to one named keychain file: `security ... -s <service> -a <account> -w
// <path>`. Set it whenever more than one keychain on the search list could
// plausibly hold an item under this service+account — e.g. a shared machine,
// or a service name that isn't guaranteed unique. New rejects a
// non-absolute path outright, mirroring WithSecurityBin: a relative path is
// ambiguous about which keychain it resolves to.
func WithKeychain(path string) Option {
	return func(s *Store) { s.keychain = path }
}

// New returns a Store scoped to the given keychain service name. The service
// name is the namespace every account lives under — convention: the consuming
// app's name (service "ferret", account "anthropic"). Empty or whitespace-only
// service names are rejected so two sloppy callers cannot silently collide in
// an unnamed namespace.
func New(service string, opts ...Option) (*Store, error) {
	if strings.TrimSpace(service) == "" {
		return nil, errors.New("keyring: service name must not be empty")
	}
	if err := printableASCIIOnly("service name", service); err != nil {
		return nil, err
	}
	s := &Store{
		service:     service,
		timeout:     defaultTimeout,
		securityBin: defaultSecurityBin,
	}
	for _, opt := range opts {
		opt(s)
	}
	if s.timeout <= 0 {
		return nil, fmt.Errorf("keyring: WithTimeout must be positive, got %s", s.timeout)
	}
	// Only meaningful where a backend exists: non-darwin builds have no
	// security binary at all (defaultSecurityBin is ""), and New must still
	// succeed there so cross-platform callers can construct a Store and let
	// GetOrEnv fall through to the environment.
	if supported && !filepath.IsAbs(s.securityBin) {
		return nil, fmt.Errorf("keyring: WithSecurityBin must be an absolute path, got %q", s.securityBin)
	}
	if s.keychain != "" && !filepath.IsAbs(s.keychain) {
		return nil, fmt.Errorf("keyring: WithKeychain must be an absolute path, got %q", s.keychain)
	}
	return s, nil
}

// Supported reports whether a real keychain backend is compiled into this
// binary — false on non-darwin builds, where every Store operation returns
// ErrUnsupported. Lets a doctor/status surface tell "backend absent" apart
// from "secret absent".
func Supported() bool { return supported && !disabled() }

// Get reads the secret stored under account. It assumes the stored value is
// printable ASCII, the contract Set enforces on write — Get itself cannot
// verify this. If an item was written by another tool (or Keychain Access)
// with bytes >=0x80, `security find-generic-password -w` hex-transcribes
// those bytes into an ASCII string with exit 0 and no error: Get would
// return that hex string as if it were the real secret, silently wrong (see
// printableASCIIOnly). Items written through this package never hit that
// case; items written elsewhere might.
func (s *Store) Get(account string) (string, error) {
	if disabled() {
		return "", errDisabled()
	}
	return s.get(account)
}

// Set stores value under account and reads it back to verify. A locked
// keychain can make `security` report success while storing nothing — the
// read-back turns that silent corruption into a hard error before the caller
// moves on. The value is piped to `security` on stdin, never placed on its
// argv, so it cannot appear in a process-table snapshot.
//
// Empty or whitespace-only account names are rejected, mirroring the empty
// service-name check in New: every empty-account write in a service would
// otherwise land on one shared slot, with -U silently overwriting whatever
// was already there.
//
// The write and the read-back are two separate `security` executions with no
// lock or transaction spanning the gap between them: an ErrVerifyFailed
// return is therefore INDETERMINATE, not confirmation the value was never
// stored — see ErrVerifyFailed. Callers must treat it as "unknown, go check"
// (Get/Has), never as "not written".
func (s *Store) Set(account, value string) error {
	if disabled() {
		return errDisabled()
	}
	if strings.TrimSpace(account) == "" {
		return errors.New("keyring: account name must not be empty")
	}
	if err := printableASCIIOnly("account", account); err != nil {
		return err
	}
	if err := printableASCIIOnlySecret("value", value); err != nil {
		return err
	}
	if err := s.write(account, value); err != nil {
		return err
	}
	got, err := s.get(account)
	if err != nil {
		return fmt.Errorf("keyring: read-back after storing %q: %w: %w (is the keychain locked?)", account, ErrVerifyFailed, err)
	}
	if got != value {
		return fmt.Errorf("keyring: read-back of %q: %w: stored value does not match", account, ErrVerifyFailed)
	}
	return nil
}

// Has reports whether a value is stored under account, returning an error the
// caller MUST block on. The three outcomes are distinct:
//   - (true, nil)  — the value was present at the moment of this read.
//   - (false, nil) — CONFIRMED not-found at the moment of this read.
//   - (false, err) — the slot could not be read (locked, denied, timed out);
//     the caller must NOT treat this as absent, or a later overwrite could
//     clobber a value that is actually there.
//
// Has is ADVISORY-ONLY, not an atomic overwrite guard: the result is stale
// the instant it returns. Set writes with `security add-generic-password
// -U` (update-if-exists), so a concurrent writer that stores a value in the
// window between this call and a following Set is silently overwritten —
// no error to either caller. The `security` CLI has no compare-and-swap;
// this package cannot offer one. Treat (false, nil) as "no value seen just
// now", and rely on it only when the account has a single writer. A future
// SetIfAbsent (skip -U, map errSecDuplicateItem/exit 45 to a sentinel) could
// close this gap for a single process, but that guard would still need to
// live with the caller, not here.
func (s *Store) Has(account string) (bool, error) {
	_, err := s.Get(account)
	switch {
	case err == nil:
		return true, nil
	case errors.Is(err, ErrNotFound):
		return false, nil
	default:
		return false, err
	}
}

// GetOrEnv reads keychain-first and falls back to os.Getenv(envVar) when the
// keychain CONFIRMS absence (ErrNotFound) or no backend exists
// (ErrUnsupported). ErrUnreadable does NOT fall through: a locked or denied
// keychain must surface as an error, never silently downgrade to the
// environment. If the fallback env var is empty or unset, the ORIGINAL
// keychain error is returned so the caller always learns why the keychain
// missed.
func (s *Store) GetOrEnv(account, envVar string) (string, error) {
	v, err := s.Get(account)
	if err == nil {
		return v, nil
	}
	if errors.Is(err, ErrNotFound) || errors.Is(err, ErrUnsupported) {
		if ev := os.Getenv(envVar); ev != "" {
			return ev, nil
		}
	}
	return "", err
}
