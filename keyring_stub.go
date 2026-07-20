//go:build !darwin

package keyring

import (
	"context"
	"fmt"
)

const supported = false

// defaultSecurityBin is unused on non-darwin builds; present so Store
// construction is platform-independent.
const defaultSecurityBin = ""

func (s *Store) get(account string) (string, error) {
	return "", fmt.Errorf("keyring: reading %q under service %q: %w", account, s.service, ErrUnsupported)
}

func (s *Store) write(account, _ string) error {
	return fmt.Errorf("keyring: storing %q under service %q: %w", account, s.service, ErrUnsupported)
}

func (s *Store) writeIfAbsent(account, _ string) error {
	return fmt.Errorf("keyring: storing %q under service %q: %w", account, s.service, ErrUnsupported)
}

func (s *Store) delete(account string) error {
	return fmt.Errorf("keyring: deleting %q under service %q: %w", account, s.service, ErrUnsupported)
}

// List returns ErrUnsupported on every non-darwin build — no keychain
// backend is compiled in. LoadManifest, by contrast, has no build tag and
// works everywhere; only the enumeration calls that hit `security` are
// platform-gated.
func (s *Store) List(_ context.Context) ([]Item, error) {
	return nil, fmt.Errorf("keyring: listing service %q: %w", s.service, ErrUnsupported)
}

// DumpDuplicates returns ErrUnsupported on every non-darwin build. It still
// validates service/opts via New so a caller sees the same argument errors
// on every platform, not just darwin.
func DumpDuplicates(_ context.Context, service string, opts ...Option) ([]DuplicateGroup, error) {
	if _, err := New(service, opts...); err != nil {
		return nil, err
	}
	return nil, fmt.Errorf("keyring: listing service %q: %w", service, ErrUnsupported)
}
