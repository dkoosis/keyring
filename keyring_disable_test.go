package keyring

import (
	"errors"
	"strings"
	"testing"
)

// TestDisableKillSwitch pins the KEYRING_DISABLE contract on EVERY platform:
// with the env var set, the Store behaves exactly like a build with no
// backend — all ops return ErrUnsupported, Supported() is false, and GetOrEnv
// falls through to the environment. This is what lets a blackbox harness that
// execs a built consumer binary guarantee the developer's real keychain never
// leaks into an env-isolated test.
func TestDisableKillSwitch(t *testing.T) {
	t.Setenv(DisableEnv, "1")

	s, err := New("keyring-disable-test")
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	if Supported() {
		t.Error("Supported() = true with kill-switch set; want false")
	}

	if _, err := s.Get("account"); !errors.Is(err, ErrUnsupported) {
		t.Errorf("Get: err = %v; want ErrUnsupported", err)
	} else if !strings.Contains(err.Error(), DisableEnv) {
		t.Errorf("Get: error %q does not name %s; an inert keychain must be diagnosable from the error text", err, DisableEnv)
	}

	if err := s.Set("account", "value"); !errors.Is(err, ErrUnsupported) {
		t.Errorf("Set: err = %v; want ErrUnsupported (must refuse the write, not store)", err)
	}

	if ok, err := s.Has("account"); ok || !errors.Is(err, ErrUnsupported) {
		t.Errorf("Has: (%v, %v); want (false, ErrUnsupported)", ok, err)
	}

	// GetOrEnv: ErrUnsupported falls through to the env var…
	t.Setenv("KEYRING_DISABLE_TEST_KEY", "from-env")
	if v, err := s.GetOrEnv("account", "KEYRING_DISABLE_TEST_KEY"); err != nil || v != "from-env" {
		t.Errorf("GetOrEnv with env fallback: (%q, %v); want (\"from-env\", nil)", v, err)
	}

	// …and with the env var empty, the original disabled error surfaces.
	t.Setenv("KEYRING_DISABLE_TEST_KEY", "")
	if _, err := s.GetOrEnv("account", "KEYRING_DISABLE_TEST_KEY"); !errors.Is(err, ErrUnsupported) {
		t.Errorf("GetOrEnv without fallback: err = %v; want ErrUnsupported", err)
	}
}

// TestDisableReadAtCallTime pins that the switch is read per call, not
// cached at New: a Store built while disabled must work once the env is
// cleared (and vice versa), so in-process tests can toggle with t.Setenv.
func TestDisableReadAtCallTime(t *testing.T) {
	t.Setenv(DisableEnv, "1")
	s, err := New("keyring-disable-test")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := s.Get("account"); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("Get while disabled: err = %v; want ErrUnsupported", err)
	}

	t.Setenv(DisableEnv, "")
	if _, err := s.Get("account"); errors.Is(err, ErrUnsupported) && supported {
		t.Errorf("Get after clearing %s on a supported platform: still ErrUnsupported; switch must be read at call time", DisableEnv)
	}
	if Supported() != supported {
		t.Errorf("Supported() = %v after clearing %s; want the platform truth %v", Supported(), DisableEnv, supported)
	}
}
