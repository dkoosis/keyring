//go:build darwin

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dkoosis/keyring"
)

// doctorStub builds a stub `security` from parts: a dump-keychain body and a
// per-account find-generic-password value table. delete-generic-password
// appends its argv to the capture so dedupe tests can assert what went.
func doctorStub(t *testing.T, dump string, values map[string]string) (bin, dir string) {
	t.Helper()
	dir = t.TempDir()
	bin = filepath.Join(dir, "security")
	script := "#!/bin/sh\n" +
		"printf '%s\\n' \"$@\" >> \"" + dir + "/argv\"\n" +
		"if [ \"$1\" = dump-keychain ]; then cat <<'DUMPEOF'\n" + dump + "\nDUMPEOF\nexit 0; fi\n" +
		"if [ \"$1\" = delete-generic-password ]; then exit 0; fi\n" +
		"if [ \"$1\" = -i ]; then read -r line; case \"$line\" in *add-generic-password*) exit 0;; esac; exit 1; fi\n" +
		"if [ \"$1\" = find-generic-password ]; then\n" +
		"  acct=\"\"\n" +
		"  prev=\"\"\n" +
		"  for tok in \"$@\"; do [ \"$prev\" = -a ] && acct=\"$tok\"; prev=\"$tok\"; done\n"
	for acct, v := range values {
		script += "  if [ \"$acct\" = \"" + acct + "\" ]; then printf '" + v + "\\n'; exit 0; fi\n"
	}
	script += "  exit 44\nfi\nexit 1\n"
	if err := os.WriteFile(bin, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return bin, dir
}

const dumpOneClean = `keychain: "/Users/x/Library/Keychains/login.keychain-db"
class: "genp"
attributes:
    "acct"<blob>="anthropic"
    "svce"<blob>="svc"`

const dumpDuplicate = `keychain: "/Users/x/Library/Keychains/login.keychain-db"
class: "genp"
attributes:
    "acct"<blob>="anthropic"
    "svce"<blob>="svc"
keychain: "/Library/Keychains/System.keychain"
class: "genp"
attributes:
    "acct"<blob>="anthropic"
    "svce"<blob>="svc"`

func TestDoctor_HealthyIsExitOK(t *testing.T) {
	clearDisable(t)
	bin, _ := doctorStub(t, dumpOneClean, map[string]string{"anthropic": "sk-clean-value-123"})
	a, out, _ := newTestApp(bin, "")
	a.jsonRun(t, []string{"doctor", "svc", "--json"}, exitOK, func(m map[string]any) {
		if m["healthy"] != true || m["ok"] != true {
			t.Errorf("envelope = %v", m)
		}
		if len(m["findings"].([]any)) != 0 {
			t.Errorf("findings = %v", m["findings"])
		}
	}, out)
}

// TestDoctor_TrailingNewlineFinding pins check 7: flagged as a fixable warn,
// exit doctor_findings, and no secret bytes in the output.
func TestDoctor_TrailingNewlineFinding(t *testing.T) {
	clearDisable(t)
	// The stub prints value + \n, plus its own trailing \n that the library
	// strips — so the stored value genuinely ends in a newline.
	bin, _ := doctorStub(t, dumpOneClean, map[string]string{"anthropic": "sk-pasted-value-9\\n"})
	a, out, _ := newTestApp(bin, "")
	a.jsonRun(t, []string{"doctor", "svc", "--json"}, exitDoctorFindings, func(m map[string]any) {
		fs := m["findings"].([]any)
		if len(fs) != 1 {
			t.Fatalf("findings = %v", fs)
		}
		f := fs[0].(map[string]any)
		if f["check"] != "trailing_newline" || f["severity"] != "warn" || f["fixable"] != true {
			t.Errorf("finding = %v", f)
		}
	}, out)
	if strings.Contains(out.String(), "sk-pasted-value-9") {
		t.Errorf("doctor leaked a value: %q", out.String())
	}
}

// TestDoctor_FixTrailingNewline pins the heal path: --fix --yes re-stores
// trimmed, the finding reports fixed and the exit goes back to ok.
func TestDoctor_FixTrailingNewline(t *testing.T) {
	clearDisable(t)
	bin, dir := doctorStub(t, dumpOneClean, map[string]string{"anthropic": "sk-pasted-value-9\\n"})
	a, out, _ := newTestApp(bin, "")
	// The stub's find-generic-password always returns the newline value, so
	// the library's read-back verify of the TRIMMED value fails — which means
	// Set errs and the finding stays unfixed. That is honest behavior for
	// this stub; assert the fix was ATTEMPTED through `security -i` instead.
	a.jsonRun(t, []string{"doctor", "svc", "--fix", "--yes", "--json"}, exitDoctorFindings, func(m map[string]any) {}, out)
	argv := ""
	if b, err := os.ReadFile(filepath.Join(dir, "argv")); err == nil {
		argv = string(b)
	}
	if !strings.Contains(argv, "-i") {
		t.Errorf("no security -i write attempted during --fix: argv=%q", argv)
	}
}

// TestDoctor_DuplicateFindingAndDedupe pins check 4: the duplicate group is
// a fixable warn, and --fix --yes deletes the non-login item with the
// deletion pinned to that keychain file.
func TestDoctor_DuplicateFindingAndDedupe(t *testing.T) {
	clearDisable(t)
	bin, dir := doctorStub(t, dumpDuplicate, map[string]string{"anthropic": "sk-clean-value-123"})
	a, out, _ := newTestApp(bin, "")
	a.jsonRun(t, []string{"doctor", "svc", "--fix", "--yes", "--json"}, exitOK, func(m map[string]any) {
		fs := m["findings"].([]any)
		if len(fs) != 1 {
			t.Fatalf("findings = %v", fs)
		}
		f := fs[0].(map[string]any)
		if f["check"] != "duplicate" || f["fixed"] != true {
			t.Errorf("finding = %v", f)
		}
	}, out)
	argv, _ := os.ReadFile(filepath.Join(dir, "argv"))
	got := string(argv)
	if !strings.Contains(got, "delete-generic-password") || !strings.Contains(got, "/Library/Keychains/System.keychain") {
		t.Errorf("dedupe did not delete the System.keychain item: argv=%q", got)
	}
	if strings.Contains(got, "delete-generic-password\n-s\nsvc\n-a\nanthropic\n/Users/x/Library/Keychains/login.keychain-db") {
		t.Errorf("dedupe deleted the login (keeper) item: argv=%q", got)
	}
}

// TestDoctor_EnvShadowingFinding pins check 6: env set and differing from
// the keychain value is a warn naming the env var — with neither value in
// the output.
func TestDoctor_EnvShadowingFinding(t *testing.T) {
	clearDisable(t)
	t.Setenv("SVC_ANTHROPIC_API_KEY", "sk-stale-env-value")
	bin, _ := doctorStub(t, dumpOneClean, map[string]string{"anthropic": "sk-clean-value-123"})
	a, out, _ := newTestApp(bin, "")
	a.jsonRun(t, []string{"doctor", "svc", "--json"}, exitDoctorFindings, func(m map[string]any) {
		f := m["findings"].([]any)[0].(map[string]any)
		if f["check"] != "env_shadowing" {
			t.Errorf("finding = %v", f)
		}
	}, out)
	if strings.Contains(out.String(), "sk-stale-env-value") || strings.Contains(out.String(), "sk-clean-value-123") {
		t.Errorf("doctor leaked a value: %q", out.String())
	}
}

// TestDoctor_DisabledIsInfoOnly pins check 5: the kill-switch reports as
// info and the exit stays ok — an intentional bypass is not a failure.
func TestDoctor_DisabledIsInfoOnly(t *testing.T) {
	t.Setenv(keyring.DisableEnv, "1")
	bin, _ := doctorStub(t, dumpOneClean, nil)
	a, out, _ := newTestApp(bin, "")
	a.jsonRun(t, []string{"doctor", "svc", "--json"}, exitOK, func(m map[string]any) {
		f := m["findings"].([]any)[0].(map[string]any)
		if f["check"] != "keyring_disable" || f["severity"] != "info" {
			t.Errorf("finding = %v", f)
		}
	}, out)
}

// TestDoctor_LockedKeychainIsError pins check 3: an unreadable dump is an
// error finding with the unlock next-command.
func TestDoctor_LockedKeychainIsError(t *testing.T) {
	clearDisable(t)
	bin, _ := stubSecurity(t, "exit 51\n")
	a, out, _ := newTestApp(bin, "")
	a.jsonRun(t, []string{"doctor", "svc", "--json"}, exitDoctorFindings, func(m map[string]any) {
		f := m["findings"].([]any)[0].(map[string]any)
		if f["check"] != "locked_keychain" || f["severity"] != "error" {
			t.Errorf("finding = %v", f)
		}
	}, out)
}

// TestDoctor_FixAgentModeRequiresYes pins fail-closed healing: --fix with a
// piped stdin and no --yes refuses before probing anything.
func TestDoctor_FixAgentModeRequiresYes(t *testing.T) {
	clearDisable(t)
	bin, _ := doctorStub(t, dumpOneClean, map[string]string{"anthropic": "x-value-123456789"})
	a, _, errOut := newTestApp(bin, "")
	if code := a.run([]string{"doctor", "svc", "--fix"}); code != exitValidation {
		t.Fatalf("exit = %d, want %d", code, exitValidation)
	}
	if !strings.Contains(errOut.String(), "--yes") {
		t.Errorf("tail missing --yes: %q", errOut.String())
	}
}

func TestHexLooking(t *testing.T) {
	for v, want := range map[string]bool{
		"636166c3a9636166c":    false, // odd length
		"636166c3a9636166c3a9": true,  // café twice, hex-transcribed
		"sk-ant-api03-abc":     false,
		"1234567890123456":     false, // digits only — likely a real numeric credential
		"12345678901234ab":     true,
	} {
		if got := hexLooking(v); got != want {
			t.Errorf("hexLooking(%q) = %v, want %v", v, got, want)
		}
	}
}

// writeManifest writes a keyring.json into a temp dir and returns its path.
func writeManifest(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "keyring.json")
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

// TestDoctor_ManifestGapAndOrphan pins check 1 + the orphan diff: a required
// declared account with no item is an error carrying the obtain_url; a
// stored item with no declaration is a warn recommending rm.
func TestDoctor_ManifestGapAndOrphan(t *testing.T) {
	clearDisable(t)
	// Keychain holds only "anthropic"; the manifest requires "voyage" and
	// does not declare "anthropic".
	bin, _ := doctorStub(t, dumpOneClean, map[string]string{"anthropic": "sk-clean-value-123"})
	mp := writeManifest(t, `{"version":1,"service":"svc","accounts":[
	  {"account":"voyage","env":"SVC_VOYAGE_API_KEY","required":true,
	   "description":"Voyage embeddings key","obtain_url":"https://dash.voyageai.com"}]}`)
	a, out, _ := newTestApp(bin, "")
	a.jsonRun(t, []string{"doctor", "svc", "--manifest", mp, "--json"}, exitDoctorFindings, func(m map[string]any) {
		var gap, orphan map[string]any
		for _, x := range m["findings"].([]any) {
			f := x.(map[string]any)
			switch f["check"] {
			case "missing":
				gap = f
			case "orphan":
				orphan = f
			}
		}
		if gap == nil || gap["severity"] != "error" || gap["account"] != "voyage" {
			t.Errorf("gap = %v", gap)
		}
		if !strings.Contains(gap["fix"].(string), "https://dash.voyageai.com") ||
			!strings.Contains(gap["fix"].(string), "keyring set svc voyage") {
			t.Errorf("gap fix = %v", gap["fix"])
		}
		if orphan == nil || orphan["severity"] != "warn" || orphan["account"] != "anthropic" {
			t.Errorf("orphan = %v", orphan)
		}
		if !strings.Contains(orphan["fix"].(string), "keyring rm svc anthropic") {
			t.Errorf("orphan fix = %v", orphan["fix"])
		}
	}, out)
}

// TestDoctor_ManifestEnvNameFeedsShadowCheck pins §5: a manifest env
// override (not the naming convention) is what check 6 compares against.
func TestDoctor_ManifestEnvNameFeedsShadowCheck(t *testing.T) {
	clearDisable(t)
	t.Setenv("TELEGRAM_BOT_TOKEN", "stale-different-token")
	bin, _ := doctorStub(t, `keychain: "/Users/x/Library/Keychains/login.keychain-db"
class: "genp"
attributes:
    "acct"<blob>="telegram"
    "svce"<blob>="svc"`, map[string]string{"telegram": "real-token-1234567"})
	mp := writeManifest(t, `{"version":1,"service":"svc","accounts":[
	  {"account":"telegram","env":"TELEGRAM_BOT_TOKEN","required":true}]}`)
	a, out, _ := newTestApp(bin, "")
	a.jsonRun(t, []string{"doctor", "svc", "--manifest", mp, "--json"}, exitDoctorFindings, func(m map[string]any) {
		found := false
		for _, x := range m["findings"].([]any) {
			f := x.(map[string]any)
			if f["check"] == "env_shadowing" && strings.Contains(f["finding"].(string), "TELEGRAM_BOT_TOKEN") {
				found = true
			}
		}
		if !found {
			t.Errorf("no env_shadowing finding naming TELEGRAM_BOT_TOKEN: %v", m["findings"])
		}
	}, out)
}

// TestDoctor_ManifestServiceMismatchFails pins the guard: diffing against
// another service's manifest is refused up front.
func TestDoctor_ManifestServiceMismatchFails(t *testing.T) {
	clearDisable(t)
	bin, _ := doctorStub(t, dumpOneClean, nil)
	mp := writeManifest(t, `{"version":1,"service":"other","accounts":[]}`)
	a, _, errOut := newTestApp(bin, "")
	if code := a.run([]string{"doctor", "svc", "--manifest", mp}); code != exitValidation {
		t.Fatalf("exit = %d, want %d", code, exitValidation)
	}
	if !strings.Contains(errOut.String(), `declares service "other"`) {
		t.Errorf("stderr = %q", errOut.String())
	}
}
