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
	// The secret must arrive on stdin (twice, prompt protocol), never on argv.
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
	if stdin := readCapture(t, dirW, "stdin"); stdin != "s3cret\ns3cret\n" {
		t.Errorf("stdin = %q, want two-line prompt protocol", stdin)
	}
	if argv := readCapture(t, dirW, "argv"); strings.Contains(argv, "s3cret") {
		t.Fatalf("SECRET ON ARGV: %q", argv)
	}
	wantArgv := "add-generic-password\n-U\n-s\nkeyring-test\n-a\nacct\n-w\n"
	if argv := readCapture(t, dirW, "argv"); argv != wantArgv {
		t.Errorf("write argv = %q, want %q", argv, wantArgv)
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
// requires KEYRING_LIVE_E2E=1 and an interactive session — `security`(1)
// reads /dev/tty for its stdin password prompt, so this cannot run headless.
func TestLiveKeychain(t *testing.T) {
	if os.Getenv("KEYRING_LIVE_E2E") != "1" {
		t.Skip("set KEYRING_LIVE_E2E=1 to run the live keychain test")
	}
	if _, err := os.Open("/dev/tty"); err != nil {
		t.Skip("no /dev/tty: security(1) cannot prompt; run interactively")
	}
	s, err := New("keyring-live-test")
	if err != nil {
		t.Fatal(err)
	}
	const acct, val = "e2e", "live-round-trip"
	if err := s.Set(acct, val); err != nil {
		t.Fatalf("live Set: %v", err)
	}
	got, err := s.Get(acct)
	if err != nil || got != val {
		t.Fatalf("live Get = (%q, %v), want (%q, nil)", got, err, val)
	}
}
