package main

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/dkoosis/keyring"
)

// migration is one planned repair. Kind names the known legacy mess; every
// applied migration is read-back verified by the library write it rides.
type migration struct {
	Kind    string `json:"migration"` // strip_trailing_newline | dedupe | legacy_rename
	Account string `json:"account"`
	Detail  string `json:"-"`
	// legacy_rename only: the old coordinates.
	fromService  string
	fromKeychain string
}

type migrationResult struct {
	Kind     string `json:"migration"`
	Account  string `json:"account"`
	Verified bool   `json:"verified,omitempty"`
	Reason   string `json:"reason,omitempty"`
}

// cmdMigrate plans and applies the known legacy repairs for one service:
// trailing-newline re-store, duplicate dedupe, and legacy-name rename
// (<service>-<provider> → <service>/<provider>, value preserved). The plan
// prints first and NOTHING applies before one confirmation — an abort
// leaves every item untouched.
func (a *app) cmdMigrate(args []string) int {
	var c common
	var yes bool
	fs := a.newFlagSet("migrate", &c)
	fs.BoolVar(&yes, "yes", false, "apply without the confirmation (required when stdin is not a terminal)")
	pos, err := parseInterspersed(fs, args)
	if err != nil {
		return exitValidation
	}
	if err := positionals(pos, &c, false); err != nil {
		return a.fail(&c, "migrate", exitValidation, err.Error()+"\n  → keyring migrate <service>")
	}

	plan, err := a.planMigrations(&c)
	if err != nil {
		return a.failErr(&c, "migrate", err)
	}
	if len(plan) == 0 {
		if c.jsonOut {
			a.emitJSON(envelope{OK: true, Code: "ok", Command: "migrate", Service: c.service},
				map[string]any{"applied": []migrationResult{}, "skipped": []migrationResult{}})
		} else {
			fmt.Fprintf(a.stdout, "✓ %s: nothing to migrate\n", c.service)
		}
		return exitOK
	}

	if !c.jsonOut || !yes {
		fmt.Fprintf(a.stderr, "migration plan for %s (%d step(s)):\n", c.service, len(plan))
		for _, m := range plan {
			fmt.Fprintf(a.stderr, "  · %s: %s\n", m.Kind, m.Detail)
		}
	}
	if !yes {
		if !a.stdinTTY {
			return a.fail(&c, "migrate", exitValidation, "refusing to migrate without confirmation\n  → add --yes to apply non-interactively")
		}
		if !a.confirm("Apply this plan?") {
			fmt.Fprintln(a.stderr, "aborted — nothing changed")
			return exitValidation
		}
	}

	applied, skipped := a.applyMigrations(&c, plan)
	if c.jsonOut {
		a.emitJSON(envelope{OK: len(skipped) == 0, Code: codeNames[migrateExit(skipped)], Command: "migrate", Service: c.service},
			map[string]any{"applied": applied, "skipped": skipped})
		return migrateExit(skipped)
	}
	for _, r := range applied {
		fmt.Fprintf(a.stdout, "✓ %s %s/%s — verified by read-back\n", r.Kind, c.service, r.Account)
	}
	for _, r := range skipped {
		fmt.Fprintf(a.stdout, "⚠ skipped %s %s/%s: %s\n", r.Kind, c.service, r.Account, r.Reason)
	}
	return migrateExit(skipped)
}

// migrateExit: fully applied = ok; anything skipped = doctor_findings, so an
// agent (or CI) can tell "healed" from "problems remain".
func migrateExit(skipped []migrationResult) int {
	if len(skipped) == 0 {
		return exitOK
	}
	return exitDoctorFindings
}

// planMigrations scans without changing anything.
func (a *app) planMigrations(c *common) ([]migration, error) {
	s, err := a.store(c)
	if err != nil {
		return nil, err
	}
	ctx := context.Background()
	var plan []migration

	// Legacy renames: any item whose SERVICE is "<service>-<provider>" —
	// the pre-convention naming (e.g. ferret-anthropic) — moves to
	// (service, provider) with its value preserved.
	all, err := keyring.DumpItems(ctx, a.storeOpts(c)...)
	if err != nil {
		return nil, err
	}
	for _, it := range all {
		provider, ok := strings.CutPrefix(it.Service, c.service+"-")
		if !ok || provider == "" {
			continue
		}
		plan = append(plan, migration{
			Kind: "legacy_rename", Account: provider,
			Detail:      fmt.Sprintf("%s/%s → %s/%s (value preserved)", it.Service, it.Account, c.service, provider),
			fromService: it.Service, fromKeychain: it.Keychain,
		})
	}

	// Duplicates.
	if groups, err := keyring.DumpDuplicates(ctx, c.service, a.storeOpts(c)...); err == nil {
		for _, g := range groups {
			plan = append(plan, migration{
				Kind: "dedupe", Account: g.Account,
				Detail: fmt.Sprintf("%d items for %s/%s — keep one, delete the rest", len(g.Items), c.service, g.Account),
			})
		}
	}

	// Trailing newlines.
	items, err := s.List(ctx)
	if err != nil {
		return nil, err
	}
	for _, it := range items {
		if v, err := s.Get(it.Account); err == nil && (strings.HasSuffix(v, "\n") || strings.HasSuffix(v, "\r")) {
			plan = append(plan, migration{
				Kind: "strip_trailing_newline", Account: it.Account,
				Detail: fmt.Sprintf("%s/%s ends in a newline — re-store trimmed", c.service, it.Account),
			})
		}
	}
	return plan, nil
}

// applyMigrations executes the confirmed plan. Every write goes through the
// library (read-back verified); every skip carries its reason.
func (a *app) applyMigrations(c *common, plan []migration) (applied, skipped []migrationResult) {
	applied, skipped = []migrationResult{}, []migrationResult{}
	s, err := a.store(c)
	if err != nil {
		for _, m := range plan {
			skipped = append(skipped, migrationResult{Kind: m.Kind, Account: m.Account, Reason: err.Error()})
		}
		return applied, skipped
	}
	for _, m := range plan {
		switch m.Kind {
		case "strip_trailing_newline":
			v, err := s.Get(m.Account)
			if err != nil {
				skipped = append(skipped, migrationResult{Kind: m.Kind, Account: m.Account, Reason: err.Error()})
				continue
			}
			trimmed := strings.TrimRight(v, "\r\n")
			if trimmed == "" {
				skipped = append(skipped, migrationResult{Kind: m.Kind, Account: m.Account, Reason: "value is only whitespace — refusing to store an empty secret"})
				continue
			}
			if err := s.Set(m.Account, trimmed); err != nil {
				skipped = append(skipped, migrationResult{Kind: m.Kind, Account: m.Account, Reason: err.Error()})
				continue
			}
			applied = append(applied, migrationResult{Kind: m.Kind, Account: m.Account, Verified: true})

		case "dedupe":
			if a.dedupeAccount(c, m.Account, true) {
				applied = append(applied, migrationResult{Kind: m.Kind, Account: m.Account, Verified: true})
			} else {
				skipped = append(skipped, migrationResult{Kind: m.Kind, Account: m.Account, Reason: "one or more duplicate deletions failed"})
			}

		case "legacy_rename":
			r := a.applyLegacyRename(c, s, m)
			if r.Reason == "" {
				applied = append(applied, r)
			} else {
				skipped = append(skipped, r)
			}
		}
	}
	return applied, skipped
}

// applyLegacyRename copies the legacy item's value to the conventional
// coordinates and deletes the legacy item only after the new write's
// read-back verified. A target that already holds a DIFFERENT value is a
// conflict — skipped, both items left in place, a human decides.
func (a *app) applyLegacyRename(c *common, s *keyring.Store, m migration) migrationResult {
	legacy, err := keyring.New(m.fromService, a.storeOpts(c)...)
	if err != nil {
		return migrationResult{Kind: m.Kind, Account: m.Account, Reason: err.Error()}
	}
	// The legacy item's ACCOUNT is whatever the old convention used
	// (commonly "api-key"); find it via the legacy service's items.
	items, err := legacy.List(context.Background())
	if err != nil || len(items) == 0 {
		return migrationResult{Kind: m.Kind, Account: m.Account, Reason: "legacy item vanished before migration"}
	}
	oldAccount := items[0].Account
	value, err := legacy.Get(oldAccount)
	if err != nil {
		return migrationResult{Kind: m.Kind, Account: m.Account, Reason: "reading legacy value: " + err.Error()}
	}
	switch err := s.SetIfAbsent(m.Account, value); {
	case err == nil:
		// stored + verified
	case errors.Is(err, keyring.ErrExists):
		existing, gerr := s.Get(m.Account)
		if gerr != nil || existing != value {
			return migrationResult{Kind: m.Kind, Account: m.Account,
				Reason: fmt.Sprintf("%s/%s already exists with a different value — resolve by hand", c.service, m.Account)}
		}
		// target already holds the same value: nothing to copy
	default:
		return migrationResult{Kind: m.Kind, Account: m.Account, Reason: err.Error()}
	}
	if err := legacy.Delete(oldAccount); err != nil {
		return migrationResult{Kind: m.Kind, Account: m.Account,
			Reason: "value migrated and verified, but deleting the legacy item failed: " + err.Error()}
	}
	return migrationResult{Kind: m.Kind, Account: m.Account, Verified: true}
}
