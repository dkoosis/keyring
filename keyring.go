// Package keyring stores and retrieves secrets in the macOS keychain via the
// `security` CLI — no cgo, no third-party dependency. Secrets never appear on
// a process argv, writes are verified by read-back, and "not found" is kept
// strictly distinct from "could not read" so callers can use presence checks
// as overwrite guards.
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
func Supported() bool { return supported }

// Get reads the secret stored under account.
func (s *Store) Get(account string) (string, error) {
	return s.get(account)
}

// Set stores value under account and reads it back to verify. A locked
// keychain can make `security` report success while storing nothing — the
// read-back turns that silent corruption into a hard error before the caller
// moves on. The value is piped to `security` on stdin, never placed on its
// argv, so it cannot appear in a process-table snapshot.
func (s *Store) Set(account, value string) error {
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
	_, err := s.get(account)
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
	v, err := s.get(account)
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
