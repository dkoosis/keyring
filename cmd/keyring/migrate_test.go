//go:build darwin

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// kvStub is a multi-item file-backed `security` stub: items live as
// kv_<service>_<account> files, dump-keychain renders them dynamically, so
// migrations that create/delete items are visible to later scans.
func kvStub(t *testing.T) (bin, dir string) {
	t.Helper()
	dir = t.TempDir()
	bin = filepath.Join(dir, "security")
	script := `#!/bin/sh
dir="` + dir + `"
if [ "$1" = dump-keychain ]; then
  for f in "$dir"/kv_*; do
    [ -f "$f" ] || continue
    base=$(basename "$f"); rest="${base#kv_}"
    svc="${rest%%__*}"; acct="${rest#*__}"
    echo "keychain: \"/Users/x/Library/Keychains/login.keychain-db\""
    echo "class: \"genp\""
    echo "attributes:"
    echo "    \"acct\"<blob>=\"$acct\""
    echo "    \"svce\"<blob>=\"$svc\""
  done
  exit 0
fi
flagval() { prev=""; for tok in "$@"; do [ "$prev" = "$want" ] && { printf '%s' "$tok"; return; }; prev="$tok"; done; }
if [ "$1" = find-generic-password ]; then
  want=-s; svc=$(flagval "$@"); want=-a; acct=$(flagval "$@")
  f="$dir/kv_${svc}__${acct}"
  [ -f "$f" ] && { cat "$f"; echo; exit 0; }
  exit 44
fi
if [ "$1" = delete-generic-password ]; then
  want=-s; svc=$(flagval "$@"); want=-a; acct=$(flagval "$@")
  f="$dir/kv_${svc}__${acct}"
  [ -f "$f" ] && { rm "$f"; exit 0; }
  exit 44
fi
if [ "$1" = -i ]; then
  read -r line
  svc=$(printf '%s' "$line" | sed 's/.*-s "\([^"]*\)".*/\1/')
  acct=$(printf '%s' "$line" | sed 's/.*-a "\([^"]*\)".*/\1/')
  val=$(printf '%s' "$line" | sed 's/.*-w "\([^"]*\)".*/\1/')
  f="$dir/kv_${svc}__${acct}"
  case "$line" in
    *"add-generic-password -U "*) printf '%s' "$val" > "$f"; exit 0 ;;
    *"add-generic-password "*)
      [ -f "$f" ] && { echo "The specified item already exists in the keychain." >&2; exit 45; }
      printf '%s' "$val" > "$f"; exit 0 ;;
  esac
  exit 1
fi
exit 1
`
	if err := os.WriteFile(bin, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return bin, dir
}

func seedItem(t *testing.T, dir, service, account, value string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, "kv_"+service+"__"+account), []byte(value), 0o644); err != nil {
		t.Fatal(err)
	}
}

func itemValue(t *testing.T, dir, service, account string) (string, bool) {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, "kv_"+service+"__"+account))
	if err != nil {
		return "", false
	}
	return string(b), true
}

// TestMigrate_LegacyRename pins the seeded-fixture AC: ferret-anthropic/
// api-key moves to ferret/anthropic with the value preserved and verified,
// and the legacy item is deleted only after.
func TestMigrate_LegacyRename(t *testing.T) {
	clearDisable(t)
	bin, dir := kvStub(t)
	seedItem(t, dir, "ferret-anthropic", "api-key", "sk-legacy-value-1")

	a, out, _ := newTestApp(bin, "")
	a.jsonRun(t, []string{"migrate", "ferret", "--yes", "--json"}, exitOK, func(m map[string]any) {
		applied := m["applied"].([]any)
		if len(applied) != 1 {
			t.Fatalf("applied = %v (skipped=%v)", applied, m["skipped"])
		}
		r := applied[0].(map[string]any)
		if r["migration"] != "legacy_rename" || r["account"] != "anthropic" || r["verified"] != true {
			t.Errorf("result = %v", r)
		}
	}, out)
	if v, ok := itemValue(t, dir, "ferret", "anthropic"); !ok || v != "sk-legacy-value-1" {
		t.Errorf("target item = %q, %v", v, ok)
	}
	if _, ok := itemValue(t, dir, "ferret-anthropic", "api-key"); ok {
		t.Error("legacy item still present after migration")
	}
}

// TestMigrate_LegacyRenameConflictSkips pins the conflict rule: a target
// holding a DIFFERENT value is never clobbered — both items stay.
func TestMigrate_LegacyRenameConflictSkips(t *testing.T) {
	clearDisable(t)
	bin, dir := kvStub(t)
	seedItem(t, dir, "ferret-anthropic", "api-key", "sk-legacy-value-1")
	seedItem(t, dir, "ferret", "anthropic", "sk-current-value-2")

	a, out, _ := newTestApp(bin, "")
	a.jsonRun(t, []string{"migrate", "ferret", "--yes", "--json"}, exitDoctorFindings, func(m map[string]any) {
		skipped := m["skipped"].([]any)
		if len(skipped) != 1 {
			t.Fatalf("skipped = %v", skipped)
		}
		r := skipped[0].(map[string]any)
		if r["migration"] != "legacy_rename" || !strings.Contains(r["reason"].(string), "different value") {
			t.Errorf("result = %v", r)
		}
	}, out)
	if v, _ := itemValue(t, dir, "ferret", "anthropic"); v != "sk-current-value-2" {
		t.Errorf("target clobbered: %q", v)
	}
	if v, _ := itemValue(t, dir, "ferret-anthropic", "api-key"); v != "sk-legacy-value-1" {
		t.Errorf("legacy item touched on conflict: %q", v)
	}
}

// TestMigrate_LegacyRenameSameValueJustDeletesLegacy pins the idempotent
// case: target already holds the same value → only the legacy item goes.
func TestMigrate_LegacyRenameSameValueJustDeletesLegacy(t *testing.T) {
	clearDisable(t)
	bin, dir := kvStub(t)
	seedItem(t, dir, "ferret-anthropic", "api-key", "sk-same-value-123")
	seedItem(t, dir, "ferret", "anthropic", "sk-same-value-123")

	a, out, _ := newTestApp(bin, "")
	a.jsonRun(t, []string{"migrate", "ferret", "--yes", "--json"}, exitOK, func(m map[string]any) {
		if len(m["applied"].([]any)) != 1 {
			t.Fatalf("applied = %v skipped = %v", m["applied"], m["skipped"])
		}
	}, out)
	if _, ok := itemValue(t, dir, "ferret-anthropic", "api-key"); ok {
		t.Error("legacy item still present")
	}
}

// TestMigrate_StripTrailingNewline pins the trim migration end-to-end
// against the kv stub: the stored value loses exactly its trailing newline.
func TestMigrate_StripTrailingNewline(t *testing.T) {
	clearDisable(t)
	bin, dir := kvStub(t)
	seedItem(t, dir, "svc", "anthropic", "sk-pasted-value-9\n")

	a, out, _ := newTestApp(bin, "")
	a.jsonRun(t, []string{"migrate", "svc", "--yes", "--json"}, exitOK, func(m map[string]any) {
		applied := m["applied"].([]any)
		if len(applied) != 1 {
			t.Fatalf("applied = %v skipped = %v", applied, m["skipped"])
		}
		if applied[0].(map[string]any)["migration"] != "strip_trailing_newline" {
			t.Errorf("applied = %v", applied)
		}
	}, out)
	if v, _ := itemValue(t, dir, "svc", "anthropic"); v != "sk-pasted-value-9" {
		t.Errorf("value = %q, want trimmed", v)
	}
}

// TestMigrate_AbortLeavesStateUntouched pins the AC: declining the plan
// changes nothing.
func TestMigrate_AbortLeavesStateUntouched(t *testing.T) {
	clearDisable(t)
	bin, dir := kvStub(t)
	seedItem(t, dir, "ferret-anthropic", "api-key", "sk-legacy-value-1")

	a, _, errOut := newTestApp(bin, "n\n")
	a.stdinTTY = true
	if code := a.run([]string{"migrate", "ferret"}); code != exitValidation {
		t.Fatalf("exit = %d, want %d", code, exitValidation)
	}
	if !strings.Contains(errOut.String(), "aborted") {
		t.Errorf("stderr = %q", errOut.String())
	}
	if v, ok := itemValue(t, dir, "ferret-anthropic", "api-key"); !ok || v != "sk-legacy-value-1" {
		t.Errorf("legacy item touched on abort: %q %v", v, ok)
	}
	if _, ok := itemValue(t, dir, "ferret", "anthropic"); ok {
		t.Error("target created on abort")
	}
}

// TestMigrate_AgentModeRequiresYes pins fail-closed: piped stdin without
// --yes refuses after printing the plan.
func TestMigrate_AgentModeRequiresYes(t *testing.T) {
	clearDisable(t)
	bin, dir := kvStub(t)
	seedItem(t, dir, "ferret-anthropic", "api-key", "sk-legacy-value-1")

	a, _, errOut := newTestApp(bin, "")
	if code := a.run([]string{"migrate", "ferret"}); code != exitValidation {
		t.Fatalf("exit = %d, want %d", code, exitValidation)
	}
	if !strings.Contains(errOut.String(), "--yes") {
		t.Errorf("stderr = %q", errOut.String())
	}
	if _, ok := itemValue(t, dir, "ferret-anthropic", "api-key"); !ok {
		t.Error("legacy item touched in fail-closed path")
	}
}

// TestMigrate_NothingToDo pins the clean exit.
func TestMigrate_NothingToDo(t *testing.T) {
	clearDisable(t)
	bin, dir := kvStub(t)
	seedItem(t, dir, "svc", "anthropic", "sk-clean-value-123")
	a, out, _ := newTestApp(bin, "")
	a.jsonRun(t, []string{"migrate", "svc", "--yes", "--json"}, exitOK, func(m map[string]any) {
		if len(m["applied"].([]any)) != 0 || len(m["skipped"].([]any)) != 0 {
			t.Errorf("plan not empty: %v", m)
		}
	}, out)
}
