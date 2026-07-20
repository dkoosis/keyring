package keyring

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeManifest(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "keyring.json")
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadManifest_ValidRoundTripsAllFields(t *testing.T) {
	path := writeManifest(t, `{
		"version": 1,
		"service": "ferret",
		"accounts": [
			{
				"account": "anthropic",
				"env": "FERRET_ANTHROPIC_API_KEY",
				"description": "Anthropic API key for ferret's analyst",
				"obtain_url": "https://platform.claude.com/settings/workspaces",
				"required": true
			},
			{ "account": "optional-thing" }
		]
	}`)
	m, err := LoadManifest(path)
	if err != nil {
		t.Fatal(err)
	}
	if m.Service != "ferret" || len(m.Accounts) != 2 {
		t.Fatalf("got service %q, %d accounts", m.Service, len(m.Accounts))
	}
	a := m.Accounts[0]
	if a.Account != "anthropic" || a.Env != "FERRET_ANTHROPIC_API_KEY" ||
		a.ObtainURL != "https://platform.claude.com/settings/workspaces" || !a.Required {
		t.Errorf("accounts[0] did not round-trip: %+v", a)
	}
	if b := m.Accounts[1]; b.Account != "optional-thing" || b.Env != "" || b.Required {
		t.Errorf("accounts[1] optional fields: %+v", b)
	}
}

func TestLoadManifest_Rejections(t *testing.T) {
	cases := []struct {
		name string
		body string
		want string // substring of the error
	}{
		{"wrong version", `{"version": 2, "service": "app", "accounts": []}`, "unsupported version 2"},
		{"missing version", `{"service": "app", "accounts": []}`, "unsupported version 0"},
		{"empty service", `{"version": 1, "service": "  ", "accounts": []}`, "service must not be empty"},
		{"non-ascii service", `{"version": 1, "service": "café", "accounts": []}`, "printable ASCII"},
		{"empty account", `{"version": 1, "service": "app", "accounts": [{"account": ""}]}`, "account must not be empty"},
		{"non-ascii obtain_url", `{"version": 1, "service": "app", "accounts": [{"account": "a", "obtain_url": "https://exämple.com"}]}`, "printable ASCII"},
		{"malformed json", `{"version": 1,`, "parsing manifest"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := LoadManifest(writeManifest(t, tc.body))
			if err == nil {
				t.Fatalf("want error containing %q, got nil", tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("want error containing %q, got %v", tc.want, err)
			}
		})
	}
}

func TestLoadManifest_MissingFile(t *testing.T) {
	if _, err := LoadManifest(filepath.Join(t.TempDir(), "nope.json")); err == nil {
		t.Fatal("want error for missing file, got nil")
	}
}
