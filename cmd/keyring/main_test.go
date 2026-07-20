//go:build darwin

package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dkoosis/keyring"
)

// stubSecurity writes an executable shell script standing in for
// /usr/bin/security (same pattern as the library's contract tests) and
// returns its path plus the capture dir.
func stubSecurity(t *testing.T, script string) (bin, dir string) {
	t.Helper()
	dir = t.TempDir()
	bin = filepath.Join(dir, "security")
	full := "#!/bin/sh\n" +
		"printf '%s\\n' \"$@\" >> \"" + dir + "/argv\"\n" +
		"cat >> \"" + dir + "/stdin\"\n" +
		script
	if err := os.WriteFile(bin, []byte(full), 0o755); err != nil {
		t.Fatal(err)
	}
	return bin, dir
}

// storeStub emulates a one-slot keychain in a file: `security -i` parses the
// -w value out of the add-generic-password line; find-generic-password -w
// prints it back; delete-generic-password empties it. Enough to drive
// set→get→rm round trips through the real library paths.
func storeStub(t *testing.T) (bin, dir string) {
	t.Helper()
	dir = t.TempDir()
	bin = filepath.Join(dir, "security")
	script := `#!/bin/sh
store="` + dir + `/store"
if [ "$1" = -i ]; then
  read -r line
  case "$line" in *"add-generic-password"*) ;; *) exit 1 ;; esac
  val="${line#*-w \"}"
  val="${val%\"}"
  if [ "$line" != "${line#*-U }" ]; then
    printf '%s' "$val" > "$store"; exit 0
  fi
  if [ -s "$store" ]; then
    echo "security: SecKeychainItemCreateFromContent: The specified item already exists in the keychain." >&2
    exit 45
  fi
  printf '%s' "$val" > "$store"; exit 0
fi
if [ "$1" = find-generic-password ]; then
  if [ -s "$store" ]; then cat "$store"; echo; exit 0; fi
  exit 44
fi
if [ "$1" = delete-generic-password ]; then
  if [ -s "$store" ]; then : > "$store"; exit 0; fi
  exit 44
fi
exit 1
`
	if err := os.WriteFile(bin, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return bin, dir
}

// newTestApp wires an app with agent-mode defaults (no TTYs) and captured
// output. Tests flip TTY bools per case.
func newTestApp(bin string, stdin string) (*app, *strings.Builder, *strings.Builder) {
	var out, errOut strings.Builder
	return &app{
		stdin:       strings.NewReader(stdin),
		stdout:      &out,
		stderr:      &errOut,
		securityBin: bin,
		readSecret: func(string) (string, error) {
			panic("hidden prompt must not fire in agent mode")
		},
	}, &out, &errOut
}

func clearDisable(t *testing.T) {
	t.Helper()
	t.Setenv(keyring.DisableEnv, "")
}

func TestRun_NoArgsIsValidation(t *testing.T) {
	a, _, errOut := newTestApp("", "")
	if code := a.run(nil); code != exitValidation {
		t.Fatalf("exit = %d, want %d", code, exitValidation)
	}
	if !strings.Contains(errOut.String(), "usage:") {
		t.Errorf("stderr missing usage: %q", errOut.String())
	}
}

// TestSet_PipedRoundTripsThroughGet pins the core AC: echo -n piped set
// works non-interactively, and get returns exactly what was stored.
func TestSet_PipedRoundTripsThroughGet(t *testing.T) {
	clearDisable(t)
	bin, _ := storeStub(t)

	a, out, _ := newTestApp(bin, "sk-test-123456")
	if code := a.run([]string{"set", "svc", "acct"}); code != exitOK {
		t.Fatalf("set exit = %d, stdout=%q", code, out.String())
	}
	if !strings.Contains(out.String(), "✓ stored svc/acct (14 bytes) — verified by read-back") {
		t.Errorf("receipt = %q", out.String())
	}

	g, gout, _ := newTestApp(bin, "")
	if code := g.run([]string{"get", "svc", "acct"}); code != exitOK {
		t.Fatalf("get exit = %d", code)
	}
	if gout.String() != "sk-test-123456\n" {
		t.Errorf("piped get = %q, want value only", gout.String())
	}
}

// TestSet_StripsTrailingNewline pins the #1 silent bug: a piped value with a
// trailing newline is stored trimmed, and the receipt says so.
func TestSet_StripsTrailingNewline(t *testing.T) {
	clearDisable(t)
	bin, _ := storeStub(t)
	a, out, _ := newTestApp(bin, "sk-test-123456\n")
	a.jsonRun(t, []string{"set", "svc", "acct", "--json"}, exitOK, func(m map[string]any) {
		if m["stripped_trailing_newline"] != true {
			t.Errorf("stripped_trailing_newline = %v, want true", m["stripped_trailing_newline"])
		}
		if m["bytes"] != float64(14) {
			t.Errorf("bytes = %v, want 14 (newline stripped)", m["bytes"])
		}
		if m["verified"] != true {
			t.Errorf("verified = %v, want true", m["verified"])
		}
	}, out)
}

// jsonRun runs args, asserts the exit code, decodes the single JSON object
// on stdout, and hands it to check.
func (a *app) jsonRun(t *testing.T, args []string, wantCode int, check func(map[string]any), out *strings.Builder) {
	t.Helper()
	if code := a.run(args); code != wantCode {
		t.Fatalf("exit = %d, want %d (stdout=%q)", code, wantCode, out.String())
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(out.String()), &m); err != nil {
		t.Fatalf("--json output does not parse: %v (%q)", err, out.String())
	}
	check(m)
}

// TestSet_ExistingWithoutForceIsExists pins write-once default: set refuses
// to clobber (exit exists) and the tail names --force.
func TestSet_ExistingWithoutForceIsExists(t *testing.T) {
	clearDisable(t)
	bin, _ := storeStub(t)
	first, _, _ := newTestApp(bin, "old-value-123")
	if code := first.run([]string{"set", "svc", "acct"}); code != exitOK {
		t.Fatalf("first set exit = %d", code)
	}

	second, out, _ := newTestApp(bin, "new-value-456")
	second.jsonRun(t, []string{"set", "svc", "acct", "--json"}, exitExists, func(m map[string]any) {
		if m["ok"] != false || m["code"] != "exists" || m["sentinel"] != "exists" {
			t.Errorf("envelope = %v", m)
		}
		if !strings.Contains(m["error"].(string), "--force") {
			t.Errorf("error tail missing --force: %v", m["error"])
		}
	}, out)

	forced, fout, _ := newTestApp(bin, "new-value-456")
	if code := forced.run([]string{"set", "svc", "acct", "--force"}); code != exitOK {
		t.Fatalf("forced set exit = %d, stdout=%q", code, fout.String())
	}
}

// TestSet_NonASCIIFailsValidationWithoutEchoingByte pins the friendly
// pre-validation: position + class only, never the offending byte, plus the
// base64 tail.
func TestSet_NonASCIIFailsValidationWithoutEchoingByte(t *testing.T) {
	clearDisable(t)
	bin, _ := storeStub(t)
	a, _, errOut := newTestApp(bin, "café")
	if code := a.run([]string{"set", "svc", "acct"}); code != exitValidation {
		t.Fatalf("exit = %d, want %d", code, exitValidation)
	}
	msg := errOut.String()
	if strings.Contains(msg, "é") || strings.Contains(msg, "caf") {
		t.Errorf("error echoes secret bytes: %q", msg)
	}
	if !strings.Contains(msg, "base64") {
		t.Errorf("error missing base64 next command: %q", msg)
	}
}

func TestSet_EmptyValueIsValidation(t *testing.T) {
	clearDisable(t)
	bin, _ := storeStub(t)
	a, _, _ := newTestApp(bin, "")
	if code := a.run([]string{"set", "svc", "acct"}); code != exitValidation {
		t.Fatalf("exit = %d, want %d", code, exitValidation)
	}
}

// TestGet_NotFoundExitAndTail pins exit 3 + the civilian next command.
func TestGet_NotFoundExitAndTail(t *testing.T) {
	clearDisable(t)
	bin, _ := stubSecurity(t, "exit 44\n")
	a, _, errOut := newTestApp(bin, "")
	if code := a.run([]string{"get", "svc", "acct"}); code != exitNotFound {
		t.Fatalf("exit = %d, want %d", code, exitNotFound)
	}
	if !strings.Contains(errOut.String(), "keyring set svc acct") {
		t.Errorf("tail missing next command: %q", errOut.String())
	}
}

// TestGet_UnreadableExit pins exit 4 on a locked/denied keychain.
func TestGet_UnreadableExit(t *testing.T) {
	clearDisable(t)
	bin, _ := stubSecurity(t, "exit 51\n")
	a, out, _ := newTestApp(bin, "")
	a.jsonRun(t, []string{"get", "svc", "acct", "--json"}, exitUnreadable, func(m map[string]any) {
		if m["code"] != "unreadable" || m["sentinel"] != "unreadable" {
			t.Errorf("envelope = %v", m)
		}
		if _, present := m["value"]; present {
			t.Error("error envelope must not carry a value key")
		}
	}, out)
}

// TestGet_MaskedOnTTY pins the ratified civilian default: masked receipt on
// a terminal, full value only with --raw.
func TestGet_MaskedOnTTY(t *testing.T) {
	clearDisable(t)
	bin, _ := storeStub(t)
	seed, _, _ := newTestApp(bin, "sk-test-123456")
	if code := seed.run([]string{"set", "svc", "acct"}); code != exitOK {
		t.Fatal("seed set failed")
	}

	a, out, _ := newTestApp(bin, "")
	a.stdoutTTY = true
	if code := a.run([]string{"get", "svc", "acct"}); code != exitOK {
		t.Fatalf("get exit = %d", code)
	}
	if strings.Contains(out.String(), "sk-test-123456") {
		t.Errorf("TTY get leaked the full value: %q", out.String())
	}
	if !strings.Contains(out.String(), "sk-t…") {
		t.Errorf("TTY get missing masked preview: %q", out.String())
	}

	raw, rout, _ := newTestApp(bin, "")
	raw.stdoutTTY = true
	if code := raw.run([]string{"get", "svc", "acct", "--raw"}); code != exitOK {
		t.Fatalf("get --raw exit = %d", code)
	}
	if rout.String() != "sk-test-123456\n" {
		t.Errorf("--raw = %q, want the value", rout.String())
	}
}

// TestGet_JSONCarriesValue pins the one envelope allowed to carry "value".
func TestGet_JSONCarriesValue(t *testing.T) {
	clearDisable(t)
	bin, _ := storeStub(t)
	seed, _, _ := newTestApp(bin, "sk-test-123456")
	if code := seed.run([]string{"set", "svc", "acct"}); code != exitOK {
		t.Fatal("seed set failed")
	}
	a, out, _ := newTestApp(bin, "")
	a.jsonRun(t, []string{"get", "svc", "acct", "--json"}, exitOK, func(m map[string]any) {
		if m["value"] != "sk-test-123456" {
			t.Errorf("value = %v", m["value"])
		}
	}, out)
}

// TestRm_AgentModeRequiresYes pins fail-closed: no TTY + no --yes = exit
// validation, nothing deleted.
func TestRm_AgentModeRequiresYes(t *testing.T) {
	clearDisable(t)
	bin, dir := storeStub(t)
	seed, _, _ := newTestApp(bin, "sk-test-123456")
	if code := seed.run([]string{"set", "svc", "acct"}); code != exitOK {
		t.Fatal("seed set failed")
	}

	a, _, errOut := newTestApp(bin, "")
	if code := a.run([]string{"rm", "svc", "acct"}); code != exitValidation {
		t.Fatalf("exit = %d, want %d", code, exitValidation)
	}
	if !strings.Contains(errOut.String(), "--yes") {
		t.Errorf("tail missing --yes: %q", errOut.String())
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "store")); len(b) == 0 {
		t.Error("item was deleted despite refusing")
	}

	yes, out, _ := newTestApp(bin, "")
	yes.jsonRun(t, []string{"rm", "svc", "acct", "--yes", "--json"}, exitOK, func(m map[string]any) {
		if m["deleted"] != true {
			t.Errorf("deleted = %v", m["deleted"])
		}
	}, out)
}

// TestRm_TTYConfirmDefaultsToNo pins the civilian confirmation: bare Enter
// (default No) aborts.
func TestRm_TTYConfirmDefaultsToNo(t *testing.T) {
	clearDisable(t)
	bin, dir := storeStub(t)
	seed, _, _ := newTestApp(bin, "sk-test-123456")
	if code := seed.run([]string{"set", "svc", "acct"}); code != exitOK {
		t.Fatal("seed set failed")
	}

	a, _, errOut := newTestApp(bin, "\n")
	a.stdinTTY = true
	if code := a.run([]string{"rm", "svc", "acct"}); code != exitValidation {
		t.Fatalf("exit = %d, want %d", code, exitValidation)
	}
	if !strings.Contains(errOut.String(), "aborted") {
		t.Errorf("stderr = %q", errOut.String())
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "store")); len(b) == 0 {
		t.Error("item was deleted on default-No")
	}

	confirmed, out, _ := newTestApp(bin, "y\n")
	confirmed.stdinTTY = true
	if code := confirmed.run([]string{"rm", "svc", "acct"}); code != exitOK {
		t.Fatalf("confirmed rm exit = %d", code)
	}
	if !strings.Contains(out.String(), "✓ deleted svc/acct") {
		t.Errorf("receipt = %q", out.String())
	}
}

// TestLs_JSONNeverPrintsValues pins ls's contract: items with attributes and
// flags, no secret bytes anywhere in the output.
func TestLs_JSONNeverPrintsValues(t *testing.T) {
	clearDisable(t)
	dir := t.TempDir()
	bin := filepath.Join(dir, "security")
	// dump-keychain returns one svc item; find-generic-password returns a
	// value WITH a stored trailing newline (value + \n + the -w newline) so
	// the trailing_newline sniff has something to classify.
	script := `#!/bin/sh
if [ "$1" = dump-keychain ]; then
cat <<'EOF'
keychain: "/Users/x/Library/Keychains/login.keychain-db"
version: 512
class: "genp"
attributes:
    "acct"<blob>="anthropic"
    "svce"<blob>="svc"
EOF
exit 0
fi
if [ "$1" = find-generic-password ]; then printf 'sk-secret-value-1\n\n'; exit 0; fi
exit 1
`
	if err := os.WriteFile(bin, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	a, out, _ := newTestApp(bin, "")
	a.jsonRun(t, []string{"ls", "svc", "--json"}, exitOK, func(m map[string]any) {
		items := m["items"].([]any)
		if len(items) != 1 {
			t.Fatalf("items = %v", items)
		}
		it := items[0].(map[string]any)
		if it["account"] != "anthropic" || it["trailing_newline"] != true {
			t.Errorf("item = %v", it)
		}
	}, out)
	if strings.Contains(out.String(), "sk-secret-value-1") {
		t.Errorf("ls leaked a value: %q", out.String())
	}
}

// TestDisabled_IsUnsupportedExit pins the kill-switch mapping: exit 7.
func TestDisabled_IsUnsupportedExit(t *testing.T) {
	t.Setenv(keyring.DisableEnv, "1")
	bin, _ := storeStub(t)
	a, out, _ := newTestApp(bin, "value-123456")
	a.jsonRun(t, []string{"get", "svc", "acct", "--json"}, exitUnsupported, func(m map[string]any) {
		if m["code"] != "unsupported" || m["sentinel"] != "unsupported" {
			t.Errorf("envelope = %v", m)
		}
	}, out)
}

func TestEnvVarFor(t *testing.T) {
	if got := envVarFor("trixi-bot", "anthropic"); got != "TRIXI_BOT_ANTHROPIC_API_KEY" {
		t.Errorf("envVarFor = %q", got)
	}
}
