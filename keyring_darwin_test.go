//go:build darwin

package keyring

import (
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
