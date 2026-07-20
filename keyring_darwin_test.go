//go:build darwin

package keyring

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// stubSecurity writes an executable shell script standing in for
// /usr/bin/security and returns its path. The script logs its argv and stdin
// to capture files so contract tests can assert the exact CLI interaction.
func stubSecurity(t *testing.T, script string) (bin, dir string) {
	t.Helper()
	dir = t.TempDir()
	bin = filepath.Join(dir, "security")
	full := "#!/bin/sh\n" +
		"printf '%s\\n' \"$@\" > \"" + dir + "/argv\"\n" +
		"cat > \"" + dir + "/stdin\"\n" +
		script
	if err := os.WriteFile(bin, []byte(full), 0o755); err != nil {
		t.Fatal(err)
	}
	return bin, dir
}

func newTestStore(t *testing.T, bin string) *Store {
	t.Helper()
	s, err := New("keyring-test")
	if err != nil {
		t.Fatal(err)
	}
	s.securityBin = bin
	return s
}

func readCapture(t *testing.T, dir, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		t.Fatalf("reading capture %s: %v", name, err)
	}
	return string(b)
}

func TestNew_RejectsEmptyService(t *testing.T) {
	for _, svc := range []string{"", "   ", "\t"} {
		if _, err := New(svc); err == nil {
			t.Errorf("New(%q): want error, got nil", svc)
		}
	}
}

func TestNew_RejectsNonPositiveTimeout(t *testing.T) {
	for _, d := range []time.Duration{0, -1 * time.Second} {
		if _, err := New("svc", WithTimeout(d)); err == nil {
			t.Errorf("New with WithTimeout(%s): want error, got nil", d)
		}
	}
}

func TestNew_RejectsRelativeSecurityBin(t *testing.T) {
	for _, bin := range []string{"security", "./security", "../bin/security"} {
		if _, err := New("svc", WithSecurityBin(bin)); err == nil {
			t.Errorf("New with WithSecurityBin(%q): want error, got nil", bin)
		}
	}
}

// TestNew_RejectsRelativeKeychain pins kr-1up: WithKeychain must reject a
// non-absolute path, the same shape as WithSecurityBin — a relative path is
// ambiguous about which keychain it resolves to.
func TestNew_RejectsRelativeKeychain(t *testing.T) {
	for _, kc := range []string{"login.keychain-db", "./login.keychain-db", "../x.keychain-db"} {
		if _, err := New("svc", WithKeychain(kc)); err == nil {
			t.Errorf("New with WithKeychain(%q): want error, got nil", kc)
		}
	}
}

// TestNew_KeychainUnsetIsDefaultBehavior pins the empty-default contract:
// WithKeychain not used at all must behave exactly as before — New succeeds
// with no keychain pin.
func TestNew_KeychainUnsetIsDefaultBehavior(t *testing.T) {
	s, err := New("svc")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if s.keychain != "" {
		t.Errorf("keychain = %q, want empty by default", s.keychain)
	}
}

func TestGet_ArgvContract(t *testing.T) {
	bin, dir := stubSecurity(t, "printf 'the-secret\\n'\nexit 0\n")
	s := newTestStore(t, bin)

	got, err := s.Get("acct")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got != "the-secret" {
		t.Errorf("Get = %q, want %q", got, "the-secret")
	}
	wantArgv := "find-generic-password\n-s\nkeyring-test\n-a\nacct\n-w\n"
	if argv := readCapture(t, dir, "argv"); argv != wantArgv {
		t.Errorf("argv = %q, want %q", argv, wantArgv)
	}
}

// TestGet_KeychainArgReachesFindGenericPassword pins kr-1up: when
// WithKeychain is set, the pinned keychain path must be appended as the
// trailing argument to find-generic-password, and be absent when unset.
func TestGet_KeychainArgReachesFindGenericPassword(t *testing.T) {
	bin, dir := stubSecurity(t, "printf 'the-secret\\n'\nexit 0\n")
	s := newTestStore(t, bin)
	s.keychain = "/Users/x/Library/Keychains/login.keychain-db"

	if _, err := s.Get("acct"); err != nil {
		t.Fatalf("Get: %v", err)
	}
	wantArgv := "find-generic-password\n-s\nkeyring-test\n-a\nacct\n-w\n" + s.keychain + "\n"
	if argv := readCapture(t, dir, "argv"); argv != wantArgv {
		t.Errorf("argv = %q, want %q", argv, wantArgv)
	}
}

func TestGet_Exit44IsNotFound(t *testing.T) {
	bin, _ := stubSecurity(t, "exit 44\n")
	s := newTestStore(t, bin)

	_, err := s.Get("acct")
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("want ErrNotFound, got %v", err)
	}
	if errors.Is(err, ErrUnreadable) {
		t.Error("exit 44 must not be ErrUnreadable")
	}
}

func TestGet_StderrNotFoundMessage(t *testing.T) {
	bin, _ := stubSecurity(t, "echo 'The specified item could not be found in the keychain.' >&2\nexit 1\n")
	s := newTestStore(t, bin)

	if _, err := s.Get("acct"); !errors.Is(err, ErrNotFound) {
		t.Errorf("want ErrNotFound from stderr match, got %v", err)
	}
}

// TestGet_StderrNotFoundWithNoiseIsNotFound pins the Contains-not-equality
// choice: macOS tools routinely emit dyld/objc warnings on stderr alongside
// the real message. The full not-found sentence amid noise is still a
// confirmed absence — an exact match would misread it as ErrUnreadable and
// break GetOrEnv's env fallback.
func TestGet_StderrNotFoundWithNoiseIsNotFound(t *testing.T) {
	bin, _ := stubSecurity(t, "echo 'objc[1234]: Class Foo is implemented in both bar and baz' >&2\necho 'The specified item could not be found in the keychain.' >&2\nexit 1\n")
	s := newTestStore(t, bin)

	if _, err := s.Get("acct"); !errors.Is(err, ErrNotFound) {
		t.Errorf("want ErrNotFound despite stderr noise, got %v", err)
	}
}

// TestGet_LockedKeychainStderrContainsPhraseIsUnreadable pins kr-jqi: a
// non-44 failure (exit 51, locked/denied-ish) whose stderr merely CONTAINS
// the not-found phrase — without being the exact known message — must still
// classify as ErrUnreadable. Otherwise Has would report safe-to-overwrite
// over a keychain slot that actually holds a live secret.
func TestGet_LockedKeychainStderrContainsPhraseIsUnreadable(t *testing.T) {
	bin, _ := stubSecurity(t, "echo 'SecKeychainFindGenericPassword: the item could not be found because the keychain is locked' >&2\nexit 51\n")
	s := newTestStore(t, bin)

	_, err := s.Get("acct")
	if !errors.Is(err, ErrUnreadable) {
		t.Errorf("want ErrUnreadable, got %v", err)
	}
	if errors.Is(err, ErrNotFound) {
		t.Error("a non-exact stderr match on a non-44 exit must NEVER classify as ErrNotFound")
	}
}

func TestGet_OtherFailureIsUnreadableNotAbsent(t *testing.T) {
	for name, script := range map[string]string{
		"exit1":  "exit 1\n",  // generic failure
		"exit51": "exit 51\n", // errSecAuthFailed-ish
	} {
		t.Run(name, func(t *testing.T) {
			bin, _ := stubSecurity(t, script)
			s := newTestStore(t, bin)

			_, err := s.Get("acct")
			if !errors.Is(err, ErrUnreadable) {
				t.Errorf("want ErrUnreadable, got %v", err)
			}
			if errors.Is(err, ErrNotFound) {
				t.Error("a non-44 failure must NEVER classify as ErrNotFound")
			}
		})
	}
}

func TestGet_TimeoutIsUnreadable(t *testing.T) {
	bin, _ := stubSecurity(t, "sleep 5\nexit 0\n")
	s := newTestStore(t, bin)
	s.timeout = 100 * time.Millisecond

	start := time.Now()
	_, err := s.Get("acct")
	if !errors.Is(err, ErrUnreadable) {
		t.Errorf("want ErrUnreadable on timeout, got %v", err)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Errorf("timeout did not bound the call: took %v", elapsed)
	}
}

func TestSet_OffArgvStdinProtocol(t *testing.T) {
	// The stub echoes the secret back on read so read-back verification passes.
	bin, dir := stubSecurity(t, `case "$1" in
find-generic-password) printf 's3cret\n' ;;
esac
exit 0
`)
	s := newTestStore(t, bin)

	if err := s.Set("acct", "s3cret"); err != nil {
		t.Fatalf("Set: %v", err)
	}
	// The secret must arrive on stdin (as a `security -i` command), never on argv.
	if argv := readCapture(t, dir, "argv"); strings.Contains(argv, "s3cret") {
		t.Fatalf("SECRET ON ARGV: %q", argv)
	}
	// The capture files hold the LAST call (the read-back), so exercise the
	// write path alone against a fresh stub to assert its argv + stdin shape.
	binW, dirW := stubSecurity(t, "exit 0\n")
	sw := newTestStore(t, binW)
	if err := sw.write("acct", "s3cret"); err != nil {
		t.Fatalf("write: %v", err)
	}
	// The whole add command — secret included, quoted — is fed to `security -i`
	// on stdin. NOT the readpassphrase prompt: that path silently truncates
	// values >128 bytes (caught live by read-back verify on a ~1kB JWT).
	wantStdin := `add-generic-password -U -s "keyring-test" -a "acct" -w "s3cret"` + "\n"
	if stdin := readCapture(t, dirW, "stdin"); stdin != wantStdin {
		t.Errorf("stdin = %q, want %q", stdin, wantStdin)
	}
	if argv := readCapture(t, dirW, "argv"); strings.Contains(argv, "s3cret") {
		t.Fatalf("SECRET ON ARGV: %q", argv)
	}
	// Argv carries only the interactive-mode flag.
	if argv := readCapture(t, dirW, "argv"); argv != "-i\n" {
		t.Errorf("write argv = %q, want %q", argv, "-i\n")
	}
}

// TestWrite_KeychainArgReachesAddGenericPassword pins kr-1up on the write
// path: the pinned keychain path must ride the `security -i` stdin command
// line as the trailing token, through the SAME quoteToken tokenizer as every
// other token — never on argv, and never unescaped.
func TestWrite_KeychainArgReachesAddGenericPassword(t *testing.T) {
	bin, dir := stubSecurity(t, "exit 0\n")
	s := newTestStore(t, bin)
	s.keychain = `/Users/x/weird "path".keychain-db`

	if err := s.write("acct", "s3cret"); err != nil {
		t.Fatalf("write: %v", err)
	}
	wantStdin := `add-generic-password -U -s "keyring-test" -a "acct" -w "s3cret" ` +
		quoteToken(s.keychain) + "\n"
	if stdin := readCapture(t, dir, "stdin"); stdin != wantStdin {
		t.Errorf("stdin = %q, want %q", stdin, wantStdin)
	}
	if argv := readCapture(t, dir, "argv"); strings.Contains(argv, "weird") {
		t.Errorf("keychain path leaked onto argv: %q", argv)
	}
}

// TestWrite_KeychainUnsetOmitsTrailingArg pins the empty-default contract on
// the write path: no WithKeychain means the stdin command line is unchanged
// from before this option existed.
func TestWrite_KeychainUnsetOmitsTrailingArg(t *testing.T) {
	bin, dir := stubSecurity(t, "exit 0\n")
	s := newTestStore(t, bin)

	if err := s.write("acct", "s3cret"); err != nil {
		t.Fatalf("write: %v", err)
	}
	wantStdin := `add-generic-password -U -s "keyring-test" -a "acct" -w "s3cret"` + "\n"
	if stdin := readCapture(t, dir, "stdin"); stdin != wantStdin {
		t.Errorf("stdin = %q, want %q", stdin, wantStdin)
	}
}

// TestQuoteToken pins the `security -i` tokenizer escaping: backslash and
// double quote escaped, everything else literal inside the quotes.
func TestQuoteToken(t *testing.T) {
	cases := []struct{ in, want string }{
		{`plain`, `"plain"`},
		{`pa"ss`, `"pa\"ss"`},
		{`pa\ss`, `"pa\\ss"`},
		{`sp ace$var`, `"sp ace$var"`},
	}
	for _, c := range cases {
		if got := quoteToken(c.in); got != c.want {
			t.Errorf("quoteToken(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// TestSet_RejectsControlChars: a newline would terminate the `security -i`
// command line and could smuggle a second command; Set must refuse before
// any process runs.
func TestSet_RejectsControlChars(t *testing.T) {
	bin, dir := stubSecurity(t, "exit 0\n")
	s := newTestStore(t, bin)
	for _, bad := range []string{"line1\nline2", "cr\rlf", "nul\x00byte", "tab\tsep"} {
		if err := s.Set("acct", bad); err == nil {
			t.Errorf("Set(%q): no error; control characters must be rejected", bad)
		}
	}
	if err := s.Set("bad\naccount", "v"); err == nil {
		t.Error("Set with newline in account: no error; must be rejected")
	}
	// No security invocation may have happened for rejected inputs — the stub
	// writes its argv capture on every call, so the file must not exist.
	if _, err := os.Stat(filepath.Join(dir, "argv")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("security was invoked for rejected input (argv capture exists, stat err=%v)", err)
	}
}

// TestSet_RejectsNonASCII pins kr-yqk: `security find-generic-password -w`
// hex-transcribes any stored value containing bytes >=0x80 on read-back (a
// live repro stored 'café' and got the literal string '636166c3a9' with
// err==nil). Since that corruption is undetectable at Get time (no marker
// distinguishes a hex transcription from a real hex-looking secret), the only
// sound contract is to refuse to store non-ASCII in the first place — for
// both the value and the account (which also rides the `security -i` command
// line).
func TestSet_RejectsNonASCII(t *testing.T) {
	bin, dir := stubSecurity(t, "exit 0\n")
	s := newTestStore(t, bin)
	for _, bad := range []string{"café", "emoji🔑token", "élite"} {
		if err := s.Set("acct", bad); err == nil {
			t.Errorf("Set(%q): no error; non-ASCII values must be rejected", bad)
		}
	}
	if err := s.Set("café-acct", "v"); err == nil {
		t.Error("Set with non-ASCII account: no error; must be rejected")
	}
	// No security invocation may have happened for rejected inputs.
	if _, err := os.Stat(filepath.Join(dir, "argv")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("security was invoked for rejected input (argv capture exists, stat err=%v)", err)
	}
}

// TestSet_ValueErrorDoesNotLeakBytes pins kr-2vk: printableASCIIOnly's error
// echoes the offending rune via %q, which is fine for service/account (not
// secret) but leaks a byte of the secret when the failing field is the
// value. The value-field error must be generic, with no byte of the
// rejected value present anywhere in the error text.
func TestSet_ValueErrorDoesNotLeakBytes(t *testing.T) {
	bin, _ := stubSecurity(t, "exit 0\n")
	s := newTestStore(t, bin)
	cases := []struct {
		name string
		bad  string
	}{
		{"non-ASCII", "café-secret-xyz"},
		{"control char", "line1\nsecret-line2"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := s.Set("acct", c.bad)
			if err == nil {
				t.Fatalf("Set(%q): no error; must be rejected", c.bad)
			}
			msg := err.Error()
			for _, r := range c.bad {
				if r < 0x20 || r > 0x7e {
					if strings.ContainsRune(msg, r) {
						t.Errorf("Set(%q): error %q contains offending rune %q from the value", c.bad, msg, r)
					}
				}
			}
			if strings.Contains(msg, c.bad) {
				t.Errorf("Set(%q): error %q contains the full offending value", c.bad, msg)
			}
		})
	}
}

// TestSet_RejectsEmptyAccount pins kr-rjx: New rejects an empty/whitespace
// service name to stop two sloppy callers from colliding in an unnamed
// namespace, but Set left the symmetric account-side hole open — every
// empty-account write in a service landed on one shared slot, with -U
// silently overwriting whatever was there. Set must refuse before any
// security invocation happens.
func TestSet_RejectsEmptyAccount(t *testing.T) {
	bin, dir := stubSecurity(t, "exit 0\n")
	s := newTestStore(t, bin)
	for _, bad := range []string{"", "   ", "\t"} {
		if err := s.Set(bad, "v"); err == nil {
			t.Errorf("Set(%q, ...): no error; empty/whitespace-only account must be rejected", bad)
		}
	}
	// No security invocation may have happened for rejected input.
	if _, err := os.Stat(filepath.Join(dir, "argv")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("security was invoked for rejected input (argv capture exists, stat err=%v)", err)
	}
}

func TestSet_ReadBackMismatchIsVerifyFailed(t *testing.T) {
	bin, _ := stubSecurity(t, `case "$1" in
find-generic-password) printf 'WRONG\n' ;;
esac
exit 0
`)
	s := newTestStore(t, bin)

	err := s.Set("acct", "right")
	if !errors.Is(err, ErrVerifyFailed) {
		t.Errorf("want ErrVerifyFailed on mismatch, got %v", err)
	}
}

func TestSet_ReadBackErrorIsVerifyFailedWithCause(t *testing.T) {
	bin, _ := stubSecurity(t, `case "$1" in
find-generic-password) exit 1 ;;
esac
exit 0
`)
	s := newTestStore(t, bin)

	err := s.Set("acct", "v")
	if !errors.Is(err, ErrVerifyFailed) {
		t.Errorf("want ErrVerifyFailed, got %v", err)
	}
	if !errors.Is(err, ErrUnreadable) {
		t.Errorf("want chained ErrUnreadable cause, got %v", err)
	}
}

// TestSet_ValuePersistsPastFailedVerify pins the ErrVerifyFailed-is-
// indeterminate contract (kr-4cd): the write (`security -i`) and the
// read-back (`find-generic-password`) are two separate executions with
// nothing spanning the gap, so a read-back failure right after a successful
// write does not mean the value was never stored. The stub makes
// add-generic-password succeed unconditionally, then fails the FIRST
// find-generic-password call (simulating a lock/deny landing between write
// and verify) while a SECOND, later call succeeds and returns the written
// value — proving the write persisted past the failed verify, exactly what
// Set must not treat as "not stored".
func TestSet_ValuePersistsPastFailedVerify(t *testing.T) {
	bin, _ := stubSecurity(t, `case "$1" in
find-generic-password)
  cf="$(dirname "$0")/find-count"
  n=0
  [ -f "$cf" ] && n=$(cat "$cf")
  n=$((n+1))
  echo "$n" > "$cf"
  if [ "$n" -eq 1 ]; then exit 1; fi
  printf 'right\n'
  ;;
esac
exit 0
`)
	s := newTestStore(t, bin)

	err := s.Set("acct", "right")
	if !errors.Is(err, ErrVerifyFailed) {
		t.Fatalf("Set: want ErrVerifyFailed on the first (failing) read-back, got %v", err)
	}

	// A later, independent Get succeeds and returns the value the write
	// stored — the ErrVerifyFailed above was indeterminate, not "unwritten".
	got, err := s.Get("acct")
	if err != nil {
		t.Fatalf("Get after failed verify: %v", err)
	}
	if got != "right" {
		t.Errorf("Get after failed verify = %q, want %q (value must persist past a failed verify)", got, "right")
	}
}

// TestSetIfAbsent_AbsentStoresAndVerifies pins the happy path: no -U on the
// wire, and a normal store + read-back verify identical to Set's, when the
// item wasn't already there.
func TestSetIfAbsent_AbsentStoresAndVerifies(t *testing.T) {
	bin, dir := stubSecurity(t, `case "$1" in
find-generic-password) printf 's3cret\n' ;;
esac
exit 0
`)
	s := newTestStore(t, bin)

	if err := s.SetIfAbsent("acct", "s3cret"); err != nil {
		t.Fatalf("SetIfAbsent: %v", err)
	}
	if argv := readCapture(t, dir, "argv"); strings.Contains(argv, "s3cret") {
		t.Fatalf("SECRET ON ARGV: %q", argv)
	}
	// Exercise writeIfAbsent alone against a fresh stub for the exact stdin
	// shape: add-generic-password WITHOUT -U.
	binW, dirW := stubSecurity(t, "exit 0\n")
	sw := newTestStore(t, binW)
	if err := sw.writeIfAbsent("acct", "s3cret"); err != nil {
		t.Fatalf("writeIfAbsent: %v", err)
	}
	wantStdin := `add-generic-password -s "keyring-test" -a "acct" -w "s3cret"` + "\n"
	if stdin := readCapture(t, dirW, "stdin"); stdin != wantStdin {
		t.Errorf("stdin = %q, want %q", stdin, wantStdin)
	}
}

// TestSetIfAbsent_ExistingItemIsErrExistsNoClobber pins the write-once
// contract: a duplicate-item failure from `security` (exit 45, the
// errSecDuplicateItem the CLI surfaces for an unconditional add against an
// existing item) must map to ErrExists — and SetIfAbsent must not fall
// through to any overwrite path or read-back-as-success on that failure.
func TestSetIfAbsent_ExistingItemIsErrExistsNoClobber(t *testing.T) {
	bin, _ := stubSecurity(t, `case "$1" in
-i) exit 45 ;;
esac
exit 0
`)
	s := newTestStore(t, bin)

	err := s.SetIfAbsent("acct", "new-value")
	if !errors.Is(err, ErrExists) {
		t.Fatalf("SetIfAbsent: want ErrExists, got %v", err)
	}
}

// TestSetIfAbsent_ExistingItemStderrMessageIsErrExists pins the stderr-text
// fallback path (mirroring isNotFound's dual exit-code/stderr contract): some
// builds may report the duplicate item via stderr text rather than exit 45.
func TestSetIfAbsent_ExistingItemStderrMessageIsErrExists(t *testing.T) {
	bin, _ := stubSecurity(t, `case "$1" in
-i)
  echo 'security: SecKeychainItemCreateFromContent: The specified item already exists in the keychain.' >&2
  exit 1
  ;;
esac
exit 0
`)
	s := newTestStore(t, bin)

	err := s.SetIfAbsent("acct", "new-value")
	if !errors.Is(err, ErrExists) {
		t.Fatalf("SetIfAbsent: want ErrExists from stderr match, got %v", err)
	}
}

// TestSetIfAbsent_OtherWriteFailureIsNotErrExists pins the inverse of the
// two tests above: a generic write failure (locked keychain, denied access)
// must never be misclassified as ErrExists — that would tell a caller "this
// account is already initialized" when the truth is "the write attempt
// itself failed".
func TestSetIfAbsent_OtherWriteFailureIsNotErrExists(t *testing.T) {
	bin, _ := stubSecurity(t, `case "$1" in
-i) exit 51 ;;
esac
exit 0
`)
	s := newTestStore(t, bin)

	err := s.SetIfAbsent("acct", "v")
	if err == nil {
		t.Fatal("SetIfAbsent: want error on write failure, got nil")
	}
	if errors.Is(err, ErrExists) {
		t.Errorf("SetIfAbsent: exit 51 must not classify as ErrExists, got %v", err)
	}
}

// TestSetIfAbsent_RejectsControlCharsAndNonASCII mirrors Set's validation
// contract (TestSet_RejectsControlChars, TestSet_RejectsNonASCII):
// SetIfAbsent must refuse bad input before any `security` invocation.
func TestSetIfAbsent_RejectsControlCharsAndNonASCII(t *testing.T) {
	bin, dir := stubSecurity(t, "exit 0\n")
	s := newTestStore(t, bin)
	for _, bad := range []string{"line1\nline2", "café", "emoji🔑token"} {
		if err := s.SetIfAbsent("acct", bad); err == nil {
			t.Errorf("SetIfAbsent(%q): no error; must be rejected", bad)
		}
	}
	if err := s.SetIfAbsent("", "v"); err == nil {
		t.Error("SetIfAbsent with empty account: no error; must be rejected")
	}
	if _, err := os.Stat(filepath.Join(dir, "argv")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("security was invoked for rejected input (argv capture exists, stat err=%v)", err)
	}
}

// TestSetIfAbsent_KeychainArgReachesAddGenericPassword pins kr-f2v honoring
// WithKeychain: the pinned keychain must ride the writeIfAbsent stdin command
// line the same way it rides write's.
func TestSetIfAbsent_KeychainArgReachesAddGenericPassword(t *testing.T) {
	bin, dir := stubSecurity(t, "exit 0\n")
	s := newTestStore(t, bin)
	s.keychain = "/Users/x/Library/Keychains/login.keychain-db"

	if err := s.writeIfAbsent("acct", "s3cret"); err != nil {
		t.Fatalf("writeIfAbsent: %v", err)
	}
	wantStdin := `add-generic-password -s "keyring-test" -a "acct" -w "s3cret" ` +
		quoteToken(s.keychain) + "\n"
	if stdin := readCapture(t, dir, "stdin"); stdin != wantStdin {
		t.Errorf("stdin = %q, want %q", stdin, wantStdin)
	}
}

func TestHas_TriState(t *testing.T) {
	t.Run("present", func(t *testing.T) {
		bin, _ := stubSecurity(t, "printf 'x\\n'\nexit 0\n")
		ok, err := newTestStore(t, bin).Has("acct")
		if !ok || err != nil {
			t.Errorf("want (true, nil), got (%v, %v)", ok, err)
		}
	})
	t.Run("confirmed-absent", func(t *testing.T) {
		bin, _ := stubSecurity(t, "exit 44\n")
		ok, err := newTestStore(t, bin).Has("acct")
		if ok || err != nil {
			t.Errorf("want (false, nil), got (%v, %v)", ok, err)
		}
	})
	t.Run("unreadable-blocks", func(t *testing.T) {
		bin, _ := stubSecurity(t, "exit 1\n")
		ok, err := newTestStore(t, bin).Has("acct")
		if ok || err == nil {
			t.Errorf("want (false, err), got (%v, %v)", ok, err)
		}
	})
}

func TestGetOrEnv_FallbackRules(t *testing.T) {
	const env = "KEYRING_TEST_FALLBACK"

	t.Run("keychain-hit-wins", func(t *testing.T) {
		t.Setenv(env, "from-env")
		bin, _ := stubSecurity(t, "printf 'from-keychain\\n'\nexit 0\n")
		v, err := newTestStore(t, bin).GetOrEnv("acct", env)
		if v != "from-keychain" || err != nil {
			t.Errorf("got (%q, %v)", v, err)
		}
	})
	t.Run("notfound-falls-to-env", func(t *testing.T) {
		t.Setenv(env, "from-env")
		bin, _ := stubSecurity(t, "exit 44\n")
		v, err := newTestStore(t, bin).GetOrEnv("acct", env)
		if v != "from-env" || err != nil {
			t.Errorf("got (%q, %v)", v, err)
		}
	})
	t.Run("notfound-empty-env-returns-original-error", func(t *testing.T) {
		t.Setenv(env, "")
		bin, _ := stubSecurity(t, "exit 44\n")
		_, err := newTestStore(t, bin).GetOrEnv("acct", env)
		if !errors.Is(err, ErrNotFound) {
			t.Errorf("want original ErrNotFound, got %v", err)
		}
	})
	t.Run("unreadable-never-falls-through", func(t *testing.T) {
		t.Setenv(env, "from-env")
		bin, _ := stubSecurity(t, "exit 1\n")
		_, err := newTestStore(t, bin).GetOrEnv("acct", env)
		if !errors.Is(err, ErrUnreadable) {
			t.Errorf("locked keychain must surface, not downgrade to env; got %v", err)
		}
	})
}

// dumpKeychainFixture is a synthetic `security dump-keychain` transcript
// covering: a "ferret/anthropic" item duplicated across two keychains (login
// + system), a "ferret/github" item present only once, and an unrelated
// "other/x" item that List/DumpDuplicates must filter out by service. Shaped
// after real `security dump-keychain` output — quoted 4-char attribute keys,
// a numeric-alias line ignored by the parser, and a "data:" section the
// parser must never read past. Also carries two records the parser must
// skip entirely: an "inet" (internet password) item — this package only
// ever creates or reads "genp" — and a genp record whose acct is <NULL>,
// which cannot become an Item because an Item without an account is
// unaddressable by every other call in the package.
const dumpKeychainFixture = `keychain: "/Users/x/Library/Keychains/login.keychain-db"
version: 512
class: "genp"
attributes:
    0x00000007 <blob>="ferret"
    "acct"<blob>="anthropic"
    "cdat"<timedate>=0x32303236303731333030303030305A00
    "svce"<blob>="ferret"
    "type"<uint32>=<NULL>
data:
"70617373776f7264"
keychain: "/Users/x/Library/Keychains/system.keychain-db"
version: 512
class: "genp"
attributes:
    "acct"<blob>="anthropic"
    "svce"<blob>="ferret"
data:
"6f74686572"
keychain: "/Users/x/Library/Keychains/login.keychain-db"
version: 512
class: "genp"
attributes:
    "acct"<blob>="github"
    "svce"<blob>="ferret"
data:
"6162630a"
keychain: "/Users/x/Library/Keychains/login.keychain-db"
version: 512
class: "genp"
attributes:
    "acct"<blob>="x"
    "svce"<blob>="other"
data:
"78797a"
keychain: "/Users/x/Library/Keychains/login.keychain-db"
version: 512
class: "inet"
attributes:
    "acct"<blob>="anthropic"
    "svce"<blob>="ferret"
data:
"696e6574"
keychain: "/Users/x/Library/Keychains/login.keychain-db"
version: 512
class: "genp"
attributes:
    "acct"<NULL>
    "svce"<blob>="ferret"
data:
"6e756c6c"
`

func TestList_ReturnsOnlyItemsForThisService(t *testing.T) {
	bin, _ := stubSecurity(t, "cat <<'EOF'\n"+dumpKeychainFixture+"EOF\nexit 0\n")
	s, err := New("ferret", WithSecurityBin(bin))
	if err != nil {
		t.Fatal(err)
	}

	items, err := s.List(context.Background())
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(items) != 3 {
		t.Fatalf("List returned %d items, want 3: %+v", len(items), items)
	}
	for _, it := range items {
		if it.Account == "x" {
			t.Errorf("List leaked an item from another service: %+v", it)
		}
	}
}

func TestList_HonorsWithKeychainArgv(t *testing.T) {
	bin, dir := stubSecurity(t, "exit 0\n")
	s, err := New("ferret", WithSecurityBin(bin), WithKeychain("/Users/x/Library/Keychains/login.keychain-db"))
	if err != nil {
		t.Fatal(err)
	}

	if _, err := s.List(context.Background()); err != nil {
		t.Fatalf("List: %v", err)
	}
	wantArgv := "dump-keychain\n/Users/x/Library/Keychains/login.keychain-db\n"
	if argv := readCapture(t, dir, "argv"); argv != wantArgv {
		t.Errorf("argv = %q, want %q", argv, wantArgv)
	}
}

func TestList_NoKeychainPinDumpsWholeSearchList(t *testing.T) {
	bin, dir := stubSecurity(t, "exit 0\n")
	s, err := New("ferret", WithSecurityBin(bin))
	if err != nil {
		t.Fatal(err)
	}

	if _, err := s.List(context.Background()); err != nil {
		t.Fatalf("List: %v", err)
	}
	wantArgv := "dump-keychain\n"
	if argv := readCapture(t, dir, "argv"); argv != wantArgv {
		t.Errorf("argv = %q, want %q — List must never pass -w", argv, wantArgv)
	}
}

func TestList_FailureIsUnreadable(t *testing.T) {
	bin, _ := stubSecurity(t, "exit 1\n")
	s, err := New("ferret", WithSecurityBin(bin))
	if err != nil {
		t.Fatal(err)
	}

	if _, err := s.List(context.Background()); !errors.Is(err, ErrUnreadable) {
		t.Errorf("want ErrUnreadable, got %v", err)
	}
}

func TestDumpDuplicates_FindsDuplicatePair(t *testing.T) {
	bin, _ := stubSecurity(t, "cat <<'EOF'\n"+dumpKeychainFixture+"EOF\nexit 0\n")

	groups, err := DumpDuplicates(context.Background(), "ferret", WithSecurityBin(bin))
	if err != nil {
		t.Fatalf("DumpDuplicates: %v", err)
	}
	if len(groups) != 1 {
		t.Fatalf("DumpDuplicates returned %d groups, want 1: %+v", len(groups), groups)
	}
	g := groups[0]
	if g.Service != "ferret" || g.Account != "anthropic" {
		t.Errorf("group = %+v, want service=ferret account=anthropic", g)
	}
	if len(g.Items) != 2 {
		t.Errorf("group has %d items, want 2", len(g.Items))
	}
}

// TestDumpDuplicates_IgnoresPinnedKeychainArgv pins the "always whole search
// list" contract: a WithKeychain option must never reach dump-keychain's
// argv, or DumpDuplicates could miss the very duplicate it exists to find.
func TestDumpDuplicates_IgnoresPinnedKeychainArgv(t *testing.T) {
	bin, dir := stubSecurity(t, "exit 0\n")

	if _, err := DumpDuplicates(context.Background(), "ferret", WithSecurityBin(bin), WithKeychain("/Users/x/Library/Keychains/login.keychain-db")); err != nil {
		t.Fatalf("DumpDuplicates: %v", err)
	}
	wantArgv := "dump-keychain\n"
	if argv := readCapture(t, dir, "argv"); argv != wantArgv {
		t.Errorf("argv = %q, want %q — DumpDuplicates must ignore WithKeychain", argv, wantArgv)
	}
}

func TestSupported_Darwin(t *testing.T) {
	if !Supported() {
		t.Error("Supported() must be true on darwin")
	}
}

// TestLiveKeychain exercises the real /usr/bin/security end-to-end. Opt-in:
// requires KEYRING_LIVE_E2E=1 and an unlocked login keychain. Runs headless —
// the `security -i` write path needs no tty (the old readpassphrase prompt,
// which did, also silently truncated values >128 bytes; see write).
func TestLiveKeychain(t *testing.T) {
	if os.Getenv("KEYRING_LIVE_E2E") != "1" {
		t.Skip("set KEYRING_LIVE_E2E=1 to run the live keychain test")
	}
	s, err := New("keyring-live-test")
	if err != nil {
		t.Fatal(err)
	}
	// A JWT-sized value: the exact shape the truncation bug ate in the wild
	// (Intuit access tokens via canapay). 100-char values masked the bug.
	val := "eyJhbGciOi." + strings.Repeat("Abc123_-", 128) + ".sig"
	const acct = "e2e"
	if err := s.Set(acct, val); err != nil {
		t.Fatalf("live Set: %v", err)
	}
	got, err := s.Get(acct)
	if err != nil || got != val {
		t.Fatalf("live Get: err=%v, len(got)=%d, want len=%d matched", err, len(got), len(val))
	}
}
