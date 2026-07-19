//go:build !darwin

package keyring

import "fmt"

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
