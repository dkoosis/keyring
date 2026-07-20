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
	args := []string{"find-generic-password", "-s", s.service, "-a", account, "-w"}
	// A pinned keychain goes last, as `security` expects for the trailing
	// keychain-file positional argument — see WithKeychain.
	if s.keychain != "" {
		args = append(args, s.keychain)
	}
	cmd := exec.CommandContext(ctx, s.securityBin, args...)
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
	line := "add-generic-password -U" +
		" -s " + quoteToken(s.service) +
		" -a " + quoteToken(account) +
		" -w " + quoteToken(value)
	// A pinned keychain goes last, same trailing-positional shape as get, and
	// through the same quoteToken tokenizer as every other token on this
	// command line — see WithKeychain.
	if s.keychain != "" {
		line += " " + quoteToken(s.keychain)
	}
	cmd.Stdin = strings.NewReader(line + "\n")
	// Capture stderr: cmd.Run leaves it nil, so a locked-keychain or
	// permission-denied message from `security` would otherwise be discarded.
	// Folding it into the error makes write failures diagnosable.
	var stderr strings.Builder
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		if stderr.Len() > 0 {
			return fmt.Errorf("keyring: storing %q: %w: %s", account, err, strings.TrimSpace(stderr.String()))
		}
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

// notFoundStderrMessage is the EXACT text `security` emits on some builds
// for a confirmed item-not-found when it exits non-44 instead. isNotFound
// requires this FULL sentence, not a fragment: a fragment match
// ("could not be found") can also appear in an unrelated failure — a locked
// keychain, a denied access dialog, or a future/localized reword — and
// wrongly classify an unreadable keychain as a confirmed absence (kr-jqi).
// That flips the ErrNotFound/ErrUnreadable invariant: Has would report
// safe-to-overwrite over a slot that may hold a live secret.
//
// Contains, not equality, on the full sentence: macOS tools routinely emit
// unrelated stderr noise (dyld/objc warnings) alongside the real message, and
// an exact match would misread a genuine absence as ErrUnreadable — breaking
// GetOrEnv's env fallback. The complete sentence is specific enough that a
// locked/denied error cannot plausibly contain it whole.
const notFoundStderrMessage = "The specified item could not be found in the keychain."

// isNotFound reports whether a `security find-generic-password` failure is a
// CONFIRMED item-not-found — exit status 44, or stderr containing the exact
// full not-found sentence. Anything else (a locked keychain, a denied access
// dialog, a timeout, or stderr that merely mentions the phrase in passing)
// is a read failure, not proof of absence.
func isNotFound(err error) bool {
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) {
		return false
	}
	if exitErr.ExitCode() == notFoundExit {
		return true
	}
	return strings.Contains(string(exitErr.Stderr), notFoundStderrMessage)
}
