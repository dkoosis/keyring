package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/dkoosis/keyring"
)

// finding is one doctor result: what's wrong, how bad, and the exact fix.
// Field names are frozen for --json (design §3.3).
type finding struct {
	Check    string `json:"check"`
	Severity string `json:"severity"` // error | warn | info
	Account  string `json:"account,omitempty"`
	Finding  string `json:"finding"`
	Fix      string `json:"fix"`
	Fixable  bool   `json:"fixable"`
	Fixed    bool   `json:"fixed"`
}

// cmdDoctor runs the no-manifest check list from design §4 — checks 2–8;
// the manifest-driven expected/orphan diff (check 1) lands with kr-7i3.3.
// No check ever prints secret bytes: values are read only to classify
// (trailing newline, hex-looking) and compare (env shadowing), never shown.
func (a *app) cmdDoctor(args []string) int {
	var c common
	var fix, yes bool
	var manifestPath string
	fs := a.newFlagSet("doctor", &c)
	fs.BoolVar(&fix, "fix", false, "apply the fixable findings (each confirmed; --yes to skip)")
	fs.BoolVar(&yes, "yes", false, "skip per-fix confirmations (required with --fix when stdin is not a terminal)")
	fs.StringVar(&manifestPath, "manifest", "", "keyring.json declaring the expected accounts (default: auto-discover)")
	pos, err := parseInterspersed(fs, args)
	if err != nil {
		return exitValidation
	}
	if err := positionals(pos, &c, false); err != nil {
		return a.fail(&c, "doctor", exitValidation, err.Error()+"\n  → keyring doctor <service>")
	}
	if fix && !yes && !a.stdinTTY {
		// Fail closed, same rule as rm: healing is destructive-adjacent and
		// never auto-proceeds unconfirmed in agent mode (design §3.1).
		return a.fail(&c, "doctor", exitValidation, "refusing to fix without confirmation\n  → add --yes to fix non-interactively")
	}

	// The manifest is optional: absent, doctor still runs every probe-based
	// check; only the expected/orphan diff needs the declaration. An
	// explicitly named manifest that fails to load IS an error — the caller
	// asked for it.
	manifest, err := discoverManifest(manifestPath, c.service)
	if err != nil {
		return a.fail(&c, "doctor", exitValidation, err.Error())
	}

	findings := a.runChecks(&c, manifest)
	if fix {
		findings = a.applyFixes(&c, findings, yes)
	}
	return a.reportDoctor(&c, findings)
}

// discoverManifest resolves the keyring.json to diff against: explicit path
// → ./keyring.json → $XDG_CONFIG_HOME/<service>/keyring.json (design §5).
// Absent everywhere is fine (nil manifest, probe-only doctor). A manifest
// naming a DIFFERENT service is an error — diffing svc A's keychain against
// svc B's declaration would produce confident nonsense.
func discoverManifest(explicit, service string) (*keyring.Manifest, error) {
	path := explicit
	if path == "" {
		for _, cand := range []string{"keyring.json", filepath.Join(xdgConfigHome(), service, "keyring.json")} {
			if _, err := os.Stat(cand); err == nil {
				path = cand
				break
			}
		}
		if path == "" {
			return nil, nil
		}
	}
	m, err := keyring.LoadManifest(path)
	if err != nil {
		return nil, err
	}
	if m.Service != service {
		return nil, fmt.Errorf("manifest %q declares service %q, not %q\n  → run: keyring doctor %s", path, m.Service, service, m.Service)
	}
	return m, nil
}

func xdgConfigHome() string {
	if x := os.Getenv("XDG_CONFIG_HOME"); x != "" {
		return x
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".config")
}

// manifestEnv returns the declared env var for account, or the naming
// convention when the manifest doesn't cover it.
func manifestEnv(m *keyring.Manifest, service, account string) string {
	if m != nil {
		for _, acc := range m.Accounts {
			if acc.Account == account && acc.Env != "" {
				return acc.Env
			}
		}
	}
	return envVarFor(service, account)
}

// runChecks executes the probe list in order. A disabled kill-switch or an
// unreadable dump short-circuits the per-item probes — there is nothing
// trustworthy left to read.
func (a *app) runChecks(c *common, manifest *keyring.Manifest) []finding {
	var findings []finding

	// Check 5 — KEYRING_DISABLE. Info, not error: an intentional bypass is
	// legitimate; doctor's job is making the silent state visible.
	if os.Getenv(keyring.DisableEnv) != "" {
		return append(findings, finding{
			Check: "keyring_disable", Severity: "info",
			Finding: keyring.DisableEnv + " is set — the keychain is bypassed, every consumer is env-only",
			Fix:     "unset " + keyring.DisableEnv + " (if unintended)",
		})
	}

	s, err := a.store(c)
	if err != nil {
		return append(findings, finding{
			Check: "store", Severity: "error",
			Finding: err.Error(),
			Fix:     "keyring doctor " + c.service + " (after fixing the arguments)",
		})
	}
	ctx := context.Background()

	// Check 3 — the dump itself readable. dump-keychain failing means
	// locked/denied: nothing below can be probed.
	items, err := s.List(ctx)
	if err != nil {
		return append(findings, finding{
			Check: "locked_keychain", Severity: "error",
			Finding: "the keychain could not be read (locked, denied, or timed out)",
			Fix:     "unlock the login keychain (Keychain Access → File → Unlock), then rerun: keyring doctor " + c.service,
		})
	}

	// Check 4 — duplicate (service,account) pairs across the search list.
	dupItems := map[string][]keyring.Item{}
	if groups, err := keyring.DumpDuplicates(ctx, c.service, a.storeOpts(c)...); err == nil {
		for _, g := range groups {
			dupItems[g.Account] = g.Items
			where := make([]string, len(g.Items))
			for i, it := range g.Items {
				where[i] = it.Keychain
			}
			findings = append(findings, finding{
				Check: "duplicate", Severity: "warn", Account: g.Account,
				Finding: fmt.Sprintf("%d items for %s/%s (%s) — reads are ambiguous",
					len(g.Items), c.service, g.Account, strings.Join(where, " + ")),
				Fix:     "keyring doctor " + c.service + " --fix (dedupe) — or pin one: --keychain <path>",
				Fixable: true,
			})
		}
	}

	// Check 1 + orphan diff — only with a manifest to diff against (§5).
	// A gap is an error: the app cannot work without a required credential.
	// An orphan is a recommendation, never an auto-delete.
	if manifest != nil {
		present := map[string]bool{}
		for _, it := range items {
			present[it.Account] = true
		}
		declared := map[string]bool{}
		for _, acc := range manifest.Accounts {
			declared[acc.Account] = true
			if acc.Required && !present[acc.Account] {
				fix := "keyring set " + c.service + " " + acc.Account
				if acc.ObtainURL != "" {
					fix = "get a key: " + acc.ObtainURL + " → then: " + fix
				}
				findings = append(findings, finding{
					Check: "missing", Severity: "error", Account: acc.Account,
					Finding: fmt.Sprintf("missing: %s/%s (%s)", c.service, acc.Account, acc.Description),
					Fix:     fix,
				})
			}
		}
		for _, it := range items {
			if !declared[it.Account] {
				findings = append(findings, finding{
					Check: "orphan", Severity: "warn", Account: it.Account,
					Finding: fmt.Sprintf("orphan: %s/%s (stored, not declared in the manifest)", c.service, it.Account),
					Fix:     "keyring rm " + c.service + " " + it.Account,
				})
			}
		}
	}

	// Per-item probes: readability (2), trailing newline (7), non-ASCII (8),
	// env shadowing (6).
	for _, it := range items {
		v, err := s.Get(it.Account)
		if err != nil {
			if errors.Is(err, keyring.ErrUnreadable) {
				findings = append(findings, finding{
					Check: "unreadable_item", Severity: "error", Account: it.Account,
					Finding: fmt.Sprintf("%s/%s exists but could not be read — keychain locked or access denied", c.service, it.Account),
					Fix:     "unlock the login keychain, or bypass: export " + keyring.DisableEnv + "=1",
				})
			}
			continue
		}
		if strings.HasSuffix(v, "\n") || strings.HasSuffix(v, "\r") {
			findings = append(findings, finding{
				Check: "trailing_newline", Severity: "warn", Account: it.Account,
				Finding: fmt.Sprintf("%s/%s ends in a newline — likely a paste error; consumers see a corrupted credential", c.service, it.Account),
				Fix:     "keyring doctor " + c.service + " --fix (re-store trimmed)",
				Fixable: true,
			})
		}
		if hexLooking(v) {
			findings = append(findings, finding{
				Check: "non_ascii", Severity: "warn", Account: it.Account,
				Finding: fmt.Sprintf("%s/%s reads back as a pure hex string (%d chars) — possibly a non-ASCII value stored by another tool, hex-transcribed on read", c.service, it.Account, len(v)),
				Fix:     "if wrong, re-store base64-encoded: base64 | keyring set " + c.service + " " + it.Account + " --stdin --force",
			})
		}
		envVar := manifestEnv(manifest, c.service, it.Account)
		if ev := os.Getenv(envVar); ev != "" && ev != v {
			findings = append(findings, finding{
				Check: "env_shadowing", Severity: "warn", Account: it.Account,
				Finding: envVar + " is set and DIFFERS from the keychain value — GetOrEnv returns the keychain, so the env var is dead weight or a stale override",
				Fix:     "unset " + envVar,
			})
		}
	}
	return findings
}

// hexLooking reports whether a value reads like `security`'s hex
// transcription of non-ASCII bytes: even-length, ≥16 chars, all lowercase
// hex digits with at least one letter (an all-digit string is far more
// likely a real numeric credential than a transcription).
func hexLooking(v string) bool {
	if len(v) < 16 || len(v)%2 != 0 {
		return false
	}
	letter := false
	for _, r := range v {
		switch {
		case r >= '0' && r <= '9':
		case r >= 'a' && r <= 'f':
			letter = true
		default:
			return false
		}
	}
	return letter
}

// applyFixes heals the fixable findings, each behind a y/N confirm unless
// yes. Healing paths:
//   - trailing_newline: re-store the trimmed value (Set, update-in-place)
//     and let the library's read-back verify it.
//   - duplicate: keep ONE item and delete the rest, each deletion pinned to
//     its keychain file so exactly the intended item goes. The kept item is
//     the login-keychain one when present (the default search list reads it
//     first), else the first found.
func (a *app) applyFixes(c *common, findings []finding, yes bool) []finding {
	s, err := a.store(c)
	if err != nil {
		return findings
	}
	for i := range findings {
		f := &findings[i]
		if !f.Fixable || f.Fixed {
			continue
		}
		switch f.Check {
		case "trailing_newline":
			if !yes && !a.confirm(fmt.Sprintf("re-store %s/%s with the trailing newline stripped?", c.service, f.Account)) {
				continue
			}
			v, err := s.Get(f.Account)
			if err != nil {
				continue
			}
			trimmed := strings.TrimRight(v, "\r\n")
			if trimmed == "" || s.Set(f.Account, trimmed) != nil {
				continue
			}
			f.Fixed = true
		case "duplicate":
			groups, err := keyring.DumpDuplicates(context.Background(), c.service, a.storeOpts(c)...)
			if err != nil {
				continue
			}
			for _, g := range groups {
				if g.Account != f.Account {
					continue
				}
				keep := pickKeeper(g.Items)
				pruned := true
				for _, it := range g.Items {
					if it.Keychain == keep.Keychain {
						continue
					}
					if !yes && !a.confirm(fmt.Sprintf("delete the duplicate %s/%s in %s (keeping the one in %s)?",
						c.service, f.Account, it.Keychain, keep.Keychain)) {
						pruned = false
						continue
					}
					pinned, err := keyring.New(c.service, append(a.storeOpts(c), keyring.WithKeychain(it.Keychain))...)
					if err != nil || pinned.Delete(f.Account) != nil {
						pruned = false
						continue
					}
				}
				f.Fixed = pruned
			}
		}
	}
	return findings
}

// pickKeeper chooses which duplicate survives a dedupe: the login-keychain
// item when present — it is what the default search list resolves — else
// the first item.
func pickKeeper(items []keyring.Item) keyring.Item {
	for _, it := range items {
		if strings.Contains(it.Keychain, "login.keychain") {
			return it
		}
	}
	return items[0]
}

// reportDoctor renders the findings and returns the exit code: ok when
// healthy (nothing, or info/fixed only), doctor_findings when any error or
// unhealed warn remains (design §3.2).
func (a *app) reportDoctor(c *common, findings []finding) int {
	counts := map[string]int{"error": 0, "warn": 0, "info": 0}
	unhealed := 0
	for _, f := range findings {
		if f.Fixed {
			continue
		}
		counts[f.Severity]++
		if f.Severity == "error" || f.Severity == "warn" {
			unhealed++
		}
	}
	healthy := unhealed == 0
	code := exitOK
	if !healthy {
		code = exitDoctorFindings
	}

	if c.jsonOut {
		list := findings
		if list == nil {
			list = []finding{}
		}
		a.emitJSON(envelope{OK: healthy, Code: codeNames[code], Command: "doctor", Service: c.service},
			map[string]any{"healthy": healthy, "findings": list, "counts": counts})
		return code
	}

	if len(findings) == 0 {
		fmt.Fprintf(a.stdout, "✓ %s: healthy — no findings\n", c.service)
		return code
	}
	for _, f := range findings {
		mark := map[string]string{"error": "✗", "warn": "⚠", "info": "ℹ"}[f.Severity]
		if f.Fixed {
			mark = "✓"
		}
		name := c.service
		if f.Account != "" {
			name = c.service + "/" + f.Account
		}
		fmt.Fprintf(a.stdout, "%s %s: %s\n", mark, name, f.Finding)
		if f.Fixed {
			fmt.Fprintf(a.stdout, "    fixed — verified by read-back\n")
		} else {
			fmt.Fprintf(a.stdout, "    → %s\n", f.Fix)
		}
	}
	if healthy {
		fmt.Fprintf(a.stdout, "✓ %s: healthy\n", c.service)
	}
	return code
}
