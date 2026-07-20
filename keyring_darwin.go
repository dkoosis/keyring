//go:build darwin

package keyring

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"time"
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
	cmd := exec.CommandContext(ctx, s.securityBin, "find-generic-password", "-s", s.service, "-a", account, "-w")
	// WaitDelay bounds the wait for the stdout pipe to close AFTER the context
	// kills the process: a grandchild inheriting the pipe (or a wedged kernel
	// call) would otherwise hold Output() open past the deadline.
	cmd.WaitDelay = time.Second
	out, err := cmd.Output()
	if err != nil {
		if isNotFound(err) {
			return "", fmt.Errorf("keyring: %q %w under service %q", account, ErrNotFound, s.service)
		}
		return "", fmt.Errorf("keyring: reading %q under service %q: %w", account, s.service, ErrUnreadable)
	}
	// Trim ONLY the trailing newline `-w` appends — TrimSpace would eat
	// whitespace that is part of the stored value and break read-back verify.
	return strings.TrimSuffix(string(out), "\n"), nil
}

// write stores value under account WITHOUT putting the secret on the process
// argv: the whole add-generic-password command is fed to `security -i`
// (interactive mode) on STDIN, so the secret lives inside the security
// process and never appears in a process-table snapshot.
//
// Why -i and not the password prompt: `security add-generic-password -w`
// with no value argument reads the password via readpassphrase(3), whose
// fixed buffer SILENTLY TRUNCATES values longer than 128 bytes — the
// read-back verify in Set caught exactly that against a live keychain (an
// Intuit access-token JWT, ~1kB). The -i command line has no such limit
// (verified live at 4kB).
//
// The -i tokenizer honors double quotes with backslash escapes, so `\` and
// `"` in the value are escaped; control characters (which would terminate or
// corrupt the command line) are rejected up front by validSecret via Set.
func (s *Store) write(account, value string) error {
	ctx, cancel := context.WithTimeout(context.Background(), s.timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, s.securityBin, "-i")
	cmd.WaitDelay = time.Second // see get: bound the post-kill pipe wait
	cmd.Stdin = strings.NewReader("add-generic-password -U" +
		" -s " + quoteToken(s.service) +
		" -a " + quoteToken(account) +
		" -w " + quoteToken(value) + "\n")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("keyring: storing %q: %w", account, err)
	}
	return nil
}

// quoteToken wraps a token for the `security -i` command tokenizer:
// double-quoted, with backslash and double-quote backslash-escaped.
func quoteToken(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	return `"` + s + `"`
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
