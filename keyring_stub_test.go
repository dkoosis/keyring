//go:build !darwin

package keyring

import (
	"context"
	"errors"
	"testing"
)

func TestStub_AllOpsReturnUnsupported(t *testing.T) {
	s, err := New("app")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Get("a"); !errors.Is(err, ErrUnsupported) {
		t.Errorf("Get: want ErrUnsupported, got %v", err)
	}
	if err := s.Set("a", "v"); !errors.Is(err, ErrUnsupported) {
		t.Errorf("Set: want ErrUnsupported, got %v", err)
	}
	if err := s.SetIfAbsent("a", "v"); !errors.Is(err, ErrUnsupported) {
		t.Errorf("SetIfAbsent: want ErrUnsupported, got %v", err)
	}
	if _, err := s.Has("a"); !errors.Is(err, ErrUnsupported) {
		t.Errorf("Has: want ErrUnsupported err, got %v", err)
	}
	if _, err := s.List(context.Background()); !errors.Is(err, ErrUnsupported) {
		t.Errorf("List: want ErrUnsupported, got %v", err)
	}
	if _, err := DumpDuplicates(context.Background(), "a"); !errors.Is(err, ErrUnsupported) {
		t.Errorf("DumpDuplicates: want ErrUnsupported, got %v", err)
	}
}

func TestStub_GetOrEnvFallsToEnv(t *testing.T) {
	const env = "KEYRING_STUB_TEST"
	t.Setenv(env, "from-env")
	s, err := New("app")
	if err != nil {
		t.Fatal(err)
	}
	v, err := s.GetOrEnv("a", env)
	if v != "from-env" || err != nil {
		t.Errorf("got (%q, %v), want (from-env, nil)", v, err)
	}
}

func TestStub_GetOrEnvEmptyEnvReturnsUnsupported(t *testing.T) {
	const env = "KEYRING_STUB_TEST_EMPTY"
	t.Setenv(env, "")
	s, err := New("app")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetOrEnv("a", env); !errors.Is(err, ErrUnsupported) {
		t.Errorf("want ErrUnsupported, got %v", err)
	}
}

func TestSupported_Stub(t *testing.T) {
	if Supported() {
		t.Error("Supported() must be false on non-darwin")
	}
}
