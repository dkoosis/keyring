//go:build darwin

package keyring

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
)

const supported = true

// defaultSecurityBin is the ABSOLUTE path to the keychain CLI. Absolute, not a
// bare "security" resolved through $PATH, so a hijacked PATH on a shared
// machine cannot substitute a malicious binary into the credential path.
// Stores copy it at construction; tests point their Store at a stub.
const defaultSecurityBin = "/usr/bin/security"

// notFoundExit is `security`'s exit status for a CONFIRMED item-not-found
// (errSecItemNotFound surfaced by the CLI). It is the ONLY non-zero status
// that means "absent"; every other failure (locked, denied, timed out) must
// not be mistaken for absence.
const notFoundExit = 44

// get reads one secret. A confirmed item-not-found is reported as
// ErrNotFound; any other `security` failure is ErrUnreadable so a caller can
// tell "no such item" (safe) from "couldn't read it" (unsafe).
func (s *Store) get(account string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), s.timeout)
	defer cancel()
	out, err := exec.CommandContext(ctx, s.securityBin, "find-generic-password", "-s", s.service, "-a", account, "-w").Output()
	if err != nil {
		if isNotFound(err) {
			return "", fmt.Errorf("keyring: %q %w under service %q", account, ErrNotFound, s.service)
		}
		return "", fmt.Errorf("keyring: reading %q under service %q: %w", account, s.service, ErrUnreadable)
	}
	return strings.TrimSpace(string(out)), nil
}

// write stores value under account WITHOUT putting the secret on the process
// argv. `security add-generic-password -w` with no value argument prompts for
// the password on stdin (enter, then retype) instead of reading it from the
// command line, so the secret is piped in and never appears in a
// process-table snapshot. The child's stdin is set explicitly, so this is
// unaffected by whatever stdin the parent holds. The prompt asks twice, so
// the value is written on two matching lines.
func (s *Store) write(account, value string) error {
	ctx, cancel := context.WithTimeout(context.Background(), s.timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, s.securityBin, "add-generic-password", "-U", "-s", s.service, "-a", account, "-w")
	cmd.Stdin = strings.NewReader(value + "\n" + value + "\n")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("keyring: storing %q: %w", account, err)
	}
	return nil
}

// isNotFound reports whether a `security find-generic-password` failure is a
// CONFIRMED item-not-found — exit status 44, or the CLI's stderr saying the
// item could not be found. Anything else (a locked keychain, a denied access
// dialog, a timeout) is a read failure, not proof of absence.
func isNotFound(err error) bool {
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) {
		return false
	}
	if exitErr.ExitCode() == notFoundExit {
		return true
	}
	return strings.Contains(string(exitErr.Stderr), "could not be found")
}
