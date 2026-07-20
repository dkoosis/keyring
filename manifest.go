package keyring

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// Manifest is the keyring.json schema v1: which accounts a service expects,
// with enough metadata for `doctor` to diagnose gaps (a required account
// with no keychain item) and orphans (an item with no manifest entry), and
// for `set` prompts to point a human at where to get the credential
// (ObtainURL). See LoadManifest.
//
// The manifest lives in this portable file — no darwin build tag — so a
// consumer can load and validate it on any platform, even one with no
// keychain backend at all.
type Manifest struct {
	Version  int       `json:"version"`
	Service  string    `json:"service"`
	Accounts []Account `json:"accounts"`
}

// Account is one manifest-declared account under a Manifest's service.
type Account struct {
	Account     string `json:"account"`
	Env         string `json:"env"`
	Description string `json:"description"`
	ObtainURL   string `json:"obtain_url"`
	Required    bool   `json:"required"`
}

// LoadManifest reads and validates a keyring.json manifest at path.
//
// Validation is strict on the fields doctor and the CLI depend on: version
// must be exactly 1 (no forward-compat guessing — a future v2 gets its own
// bead), service must be non-empty, and every string field (service,
// account, env, description, obtain_url) must be printable ASCII, the same
// contract Set enforces on values — a manifest is checked into a repo and
// rendered in terminal output, so it gets no more latitude than a keychain
// account name. Optional fields (env, description, obtain_url) may be
// empty; when present they are still ASCII-validated.
func LoadManifest(path string) (*Manifest, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("keyring: reading manifest %q: %w", path, err)
	}
	var m Manifest
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, fmt.Errorf("keyring: parsing manifest %q: %w", path, err)
	}
	if m.Version != 1 {
		return nil, fmt.Errorf("keyring: manifest %q: unsupported version %d, want 1", path, m.Version)
	}
	if strings.TrimSpace(m.Service) == "" {
		return nil, fmt.Errorf("keyring: manifest %q: service must not be empty", path)
	}
	if err := printableASCIIOnly("manifest service", m.Service); err != nil {
		return nil, fmt.Errorf("keyring: manifest %q: %w", path, err)
	}
	for i, a := range m.Accounts {
		if strings.TrimSpace(a.Account) == "" {
			return nil, fmt.Errorf("keyring: manifest %q: accounts[%d].account must not be empty", path, i)
		}
		fields := []struct{ name, val string }{
			{"account", a.Account},
			{"env", a.Env},
			{"description", a.Description},
			{"obtain_url", a.ObtainURL},
		}
		for _, f := range fields {
			if f.val == "" {
				continue // optional fields may be empty
			}
			if err := printableASCIIOnly(fmt.Sprintf("manifest accounts[%d].%s", i, f.name), f.val); err != nil {
				return nil, fmt.Errorf("keyring: manifest %q: %w", path, err)
			}
		}
	}
	return &m, nil
}
