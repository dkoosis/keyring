// Package keyring stores and retrieves secrets in the macOS keychain via the
// `security` CLI — no cgo, no third-party dependency. Secrets never appear on
// a process argv, writes are verified by read-back, and "not found" is kept
// strictly distinct from "could not read" so callers can use presence checks
// as overwrite guards.
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
}

// Option configures a Store.
type Option func(*Store)

// WithTimeout overrides the per-invocation timeout (default 10s).
func WithTimeout(d time.Duration) Option {
	return func(s *Store) { s.timeout = d }
}

// WithSecurityBin overrides the path to the `security` binary. FOR TESTS
// ONLY — it exists so consumers can point a Store at a stub and assert the
// CLI contract. Production code must keep the default absolute path; a
// relative or $PATH-resolved override reopens the PATH-hijack hole the
// default exists to close.
func WithSecurityBin(path string) Option {
	return func(s *Store) { s.securityBin = path }
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
func (s *Store) Set(account, value string) error {
	if disabled() {
		return errDisabled()
	}
	if err := printableASCIIOnly("account", account); err != nil {
		return err
	}
	if err := printableASCIIOnly("value", value); err != nil {
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
//   - (true, nil)  — the value is present.
//   - (false, nil) — CONFIRMED not-found; safe to write.
//   - (false, err) — the slot could not be read (locked, denied, timed out);
//     the caller must NOT treat this as absent, or a later overwrite could
//     clobber a value that is actually there.
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
