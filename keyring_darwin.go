//go:build darwin

package keyring

import (
	"context"
	"encoding/hex"
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
	stderr, err := s.doWrite(account, value, true)
	if err != nil {
		if stderr != "" {
			return fmt.Errorf("keyring: storing %q: %w: %s", account, err, strings.TrimSpace(stderr))
		}
		return fmt.Errorf("keyring: storing %q: %w", account, err)
	}
	return nil
}

// writeIfAbsent stores value under account WITHOUT -U: `security
// add-generic-password` then fails with a confirmed duplicate-item error
// (see isDuplicateItem) instead of silently overwriting an existing item.
// That failure is mapped to ErrExists; everything else — secret-on-stdin,
// quoting, WithKeychain — matches write. See SetIfAbsent.
func (s *Store) writeIfAbsent(account, value string) error {
	stderr, err := s.doWrite(account, value, false)
	if err != nil {
		if isDuplicateItem(err, stderr) {
			return fmt.Errorf("keyring: %q %w under service %q", account, ErrExists, s.service)
		}
		if stderr != "" {
			return fmt.Errorf("keyring: storing %q: %w: %s", account, err, strings.TrimSpace(stderr))
		}
		return fmt.Errorf("keyring: storing %q: %w", account, err)
	}
	return nil
}

// doWrite runs `security -i` with an add-generic-password command line,
// with or without -U per update, and returns captured stderr alongside
// whatever error cmd.Run produced. write and writeIfAbsent classify that
// error differently (generic failure vs. confirmed duplicate-item), so the
// process-invocation plumbing lives here once and the classification stays
// in each caller.
func (s *Store) doWrite(account, value string, update bool) (stderr string, err error) {
	ctx, cancel := context.WithTimeout(context.Background(), s.timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, s.securityBin, "-i")
	cmd.WaitDelay = time.Second // see get: bound the post-kill pipe wait
	verb := "add-generic-password"
	if update {
		verb += " -U"
	}
	line := verb +
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
	// Capture stderr: cmd.Run leaves it nil, so a locked-keychain, duplicate-
	// item, or permission-denied message from `security` would otherwise be
	// discarded. Folding it into the error (or classifying on it) makes
	// failures diagnosable.
	var errBuf strings.Builder
	cmd.Stderr = &errBuf
	err = cmd.Run()
	return errBuf.String(), err
}

// quoteToken wraps a token for the `security -i` command tokenizer:
// double-quoted, with backslash and double-quote backslash-escaped.
func quoteToken(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	return `"` + s + `"`
}

// delete removes one item via `security delete-generic-password`. Only
// attributes ride the argv — service and account are not secrets — and the
// command never reads or prints the stored value. Classification mirrors
// get: exit 44 / the exact not-found sentence is a CONFIRMED absence
// (ErrNotFound); anything else is ErrUnreadable, never proof the item was
// gone.
func (s *Store) delete(account string) error {
	ctx, cancel := context.WithTimeout(context.Background(), s.timeout)
	defer cancel()
	args := []string{"delete-generic-password", "-s", s.service, "-a", account}
	// A pinned keychain goes last, the same trailing-positional shape as
	// get/write — see WithKeychain.
	if s.keychain != "" {
		args = append(args, s.keychain)
	}
	cmd := exec.CommandContext(ctx, s.securityBin, args...)
	cmd.WaitDelay = time.Second // see get: bound the post-kill pipe wait
	if _, err := cmd.Output(); err != nil {
		if isNotFound(err) {
			return fmt.Errorf("keyring: %q %w under service %q", account, ErrNotFound, s.service)
		}
		return fmt.Errorf("keyring: deleting %q under service %q: %w", account, s.service, ErrUnreadable)
	}
	return nil
}

// notFoundStderrMessage is the EXACT text `security` emits on some builds
// for a confirmed item-not-found when it exits non-44 instead. isNotFound
// requires this FULL sentence, not a fragment: a fragment match
// ("could not be found") can also appear in an unrelated failure — a locked
// keychain, a denied access dialog, or a future/localized reword — and
// wrongly classify an unreadable keychain as a confirmed absence.
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

// duplicateItemExit is `security`'s exit status for a CONFIRMED duplicate
// item on an unconditional add-generic-password (errSecDuplicateItem
// surfaced by the CLI) — the failure writeIfAbsent relies on instead of -U's
// silent overwrite. Mirrors notFoundExit's role for find-generic-password.
const duplicateItemExit = 45

// duplicateItemStderrMessage is the fallback text match for a duplicate-item
// failure, mirroring notFoundStderrMessage: some builds may report a
// duplicate item via stderr text rather than (or alongside) exit 45.
// Contains, not equality, for the same reason as notFoundStderrMessage —
// macOS tools routinely emit dyld/objc noise on stderr alongside the real
// message.
const duplicateItemStderrMessage = "The specified item already exists in the keychain."

// isDuplicateItem reports whether an add-generic-password failure is a
// CONFIRMED duplicate item — exit status 45, or stderr containing the exact
// full duplicate-item sentence. Anything else must not be classified as
// ErrExists: writeIfAbsent's caller (SetIfAbsent) treats every other failure
// as an ordinary write error, never as "the item is already there".
//
// Unlike isNotFound, which reads exitErr.Stderr (populated by cmd.Output()),
// this takes the captured stderr text directly: writeIfAbsent's underlying
// doWrite runs cmd.Run() with cmd.Stderr redirected to its own buffer, so
// cmd.Run's *exec.ExitError never gets its Stderr field populated the way
// Output() populates it.
func isDuplicateItem(err error, stderr string) bool {
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) {
		return false
	}
	if exitErr.ExitCode() == duplicateItemExit {
		return true
	}
	return strings.Contains(stderr, duplicateItemStderrMessage)
}

// List returns every item under this store's service, found via `security
// dump-keychain` — WITHOUT -w, so only attributes (account, keychain path)
// are read; no code path here ever touches secret bytes. When a keychain is
// pinned via WithKeychain, List scopes dump-keychain to just that file
// (dump-keychain's trailing positional argument, same shape as get/write);
// otherwise it dumps the whole default search list.
func (s *Store) List(ctx context.Context) ([]Item, error) {
	if disabled() {
		return nil, errDisabled()
	}
	out, err := s.runDumpKeychain(ctx, s.keychain)
	if err != nil {
		return nil, err
	}
	var items []Item
	for _, e := range parseDumpKeychain(out) {
		if e.service == s.service {
			items = append(items, Item{Account: e.account, Keychain: e.keychain})
		}
	}
	return items, nil
}

// DumpDuplicates scans the WHOLE keychain search list — never a single
// pinned keychain, which would defeat its purpose — for every item under
// service, groups by account, and returns only the groups with more than
// one item. This is the primitive doctor's duplicate-item check (design §4
// check 4) is built on: a duplicate (service, account) pair across the
// search list is exactly the ambiguity WithKeychain exists to close (see
// WithKeychain's doc comment). Uses `security dump-keychain` without -w:
// attributes only, no secret bytes read.
//
// opts configures the underlying Store used to run the command (timeout,
// WithSecurityBin for tests); any WithKeychain passed in opts is ignored —
// DumpDuplicates always scans the full search list regardless.
func DumpDuplicates(ctx context.Context, service string, opts ...Option) ([]DuplicateGroup, error) {
	if disabled() {
		return nil, errDisabled()
	}
	s, err := New(service, opts...)
	if err != nil {
		return nil, err
	}
	out, err := s.runDumpKeychain(ctx, "") // "" = whole search list, always
	if err != nil {
		return nil, err
	}
	byAccount := map[string][]Item{}
	var order []string
	for _, e := range parseDumpKeychain(out) {
		if e.service != service {
			continue
		}
		if _, seen := byAccount[e.account]; !seen {
			order = append(order, e.account)
		}
		byAccount[e.account] = append(byAccount[e.account], Item{Account: e.account, Keychain: e.keychain})
	}
	var groups []DuplicateGroup
	for _, acct := range order {
		items := byAccount[acct]
		if len(items) > 1 {
			groups = append(groups, DuplicateGroup{Service: service, Account: acct, Items: items})
		}
	}
	return groups, nil
}

// runDumpKeychain runs `security dump-keychain` — WITHOUT -w and WITHOUT -d,
// so the "data:" section (if present at all) is never populated with the
// actual secret bytes; this command line cannot read a value even by
// accident. keychain, if non-empty, is appended as dump-keychain's trailing
// positional argument to scope the dump to one file; empty means the whole
// default search list.
//
// A non-zero exit here is classified as ErrUnreadable, not ErrNotFound:
// unlike find-generic-password, dump-keychain has no "confirmed absent"
// outcome to detect — an empty keychain dumps successfully with empty
// output — so any failure means the dump itself could not be read (locked,
// denied, timed out, or a bad --keychain path).
func (s *Store) runDumpKeychain(ctx context.Context, keychain string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()
	args := []string{"dump-keychain"}
	if keychain != "" {
		args = append(args, keychain)
	}
	cmd := exec.CommandContext(ctx, s.securityBin, args...)
	// WaitDelay bounds the wait for the stdout pipe to close AFTER the context
	// kills the process — see get's identical rationale.
	cmd.WaitDelay = time.Second
	// Capture stderr: cmd.Output leaves it discarded here, so a locked-keychain
	// or permission-denied message would otherwise be lost. Fold it into the
	// error to make failures diagnosable.
	var errBuf strings.Builder
	cmd.Stderr = &errBuf
	out, err := cmd.Output()
	if err != nil {
		if e := strings.TrimSpace(errBuf.String()); e != "" {
			return "", fmt.Errorf("keyring: dump-keychain: %w: %s", ErrUnreadable, e)
		}
		return "", fmt.Errorf("keyring: dump-keychain: %w", ErrUnreadable)
	}
	return string(out), nil
}

// dumpEntry is one parsed `security dump-keychain` record: enough to build
// an Item, plus the service name List/DumpDuplicates filter on.
type dumpEntry struct {
	keychain string
	service  string
	account  string
}

// dumpKeychainClass is the item class dump-keychain reports for a generic
// password (as opposed to "inet", an internet password) — the only class
// this package's Set/Get/List ever create or read.
const dumpKeychainClass = "genp"

// parseDumpKeychain parses `security dump-keychain` output (attributes
// only — see runDumpKeychain) into entries. Liberal in what it tolerates:
// unknown attribute keys, attribute lines it doesn't recognize, and
// keychains with zero items are all fine. Strict in what it emits: only
// "genp" entries with BOTH svce and acct populated become a dumpEntry, and
// parsing never looks past a "data:" line — even if a caller somehow ran
// this against dump-keychain -d output, the value bytes are never read.
//
// Each record in the real output looks like:
//
//	keychain: "/Users/x/Library/Keychains/login.keychain-db"
//	version: 512
//	class: "genp"
//	attributes:
//	    "acct"<blob>="anthropic"
//	    ...
//	    "svce"<blob>="ferret"
//	data:
//	<not parsed — see above>
func parseDumpKeychain(out string) []dumpEntry {
	var entries []dumpEntry
	var keychain, class, service, account string
	inAttrs := false
	flush := func() {
		if class == dumpKeychainClass && service != "" && account != "" {
			entries = append(entries, dumpEntry{keychain: keychain, service: service, account: account})
		}
		class, service, account = "", "", ""
		inAttrs = false
	}
	for line := range strings.SplitSeq(out, "\n") {
		trimmed := strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(trimmed, "keychain: "):
			flush()
			keychain = unquoteDump(strings.TrimPrefix(trimmed, "keychain: "))
		case strings.HasPrefix(trimmed, "class: "):
			class = unquoteDump(strings.TrimPrefix(trimmed, "class: "))
		case trimmed == "attributes:":
			inAttrs = true
		case trimmed == "data:":
			inAttrs = false // never parse past this point — see doc comment
		case inAttrs:
			if k, v, ok := parseDumpAttrLine(trimmed); ok {
				switch k {
				case "svce":
					service = v
				case "acct":
					account = v
				}
			}
		}
	}
	flush()
	return entries
}

// parseDumpAttrLine parses one attribute line of the form
// `"key"<type>=value`, where value is a double-quoted string, <NULL>, or a
// 0x-prefixed hex blob. Lines in other forms (including the numeric
// 0x00000007-style key alias dump-keychain also emits for some attributes)
// are not recognized and return ok=false — parseDumpKeychain only needs the
// quoted-key "acct"/"svce" form, which is what current `security` emits.
func parseDumpAttrLine(line string) (key, value string, ok bool) {
	if !strings.HasPrefix(line, `"`) {
		return "", "", false
	}
	rest := line[1:]
	end := strings.Index(rest, `"`)
	if end < 0 {
		return "", "", false
	}
	key = rest[:end]
	rest = rest[end+1:]
	_, after, found := strings.Cut(rest, "=")
	if !found {
		return "", "", false
	}
	raw := strings.TrimSpace(after)
	switch {
	case raw == "<NULL>":
		return key, "", true
	case strings.HasPrefix(raw, `"`) && strings.HasSuffix(raw, `"`) && len(raw) >= 2:
		return key, unquoteDump(raw), true
	case strings.HasPrefix(raw, "0x"):
		// A hex-encoded blob — dump-keychain's fallback rendering for a value
		// that isn't cleanly printable. account/service names are ASCII by
		// this package's own contract, so this is a defensive decode for
		// items written by another tool, not the expected path. dump-keychain
		// often appends the printable rendering after the hex run
		// (e.g. `0x616E74...  "anthropic"`); keep only the leading hex digits,
		// or DecodeString fails on the trailing bytes and the item is dropped.
		h := raw[2:]
		if j := strings.IndexFunc(h, func(r rune) bool {
			return !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F'))
		}); j >= 0 {
			h = h[:j]
		}
		if b, err := hex.DecodeString(h); err == nil {
			return key, string(b), true
		}
		return key, "", true
	default:
		return key, raw, true
	}
}

// unquoteDump strips a double-quoted dump-keychain token and unescapes the
// two sequences `security` emits inside one: `\"` and `\\`.
func unquoteDump(s string) string {
	s = strings.TrimSpace(s)
	if len(s) >= 2 && strings.HasPrefix(s, `"`) && strings.HasSuffix(s, `"`) {
		s = s[1 : len(s)-1]
		s = strings.ReplaceAll(s, `\"`, `"`)
		s = strings.ReplaceAll(s, `\\`, `\`)
	}
	return s
}
