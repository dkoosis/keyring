// Command keyring is the CLI skin over the keyring library: set/get/ls/rm
// for macOS keychain items, serving two audiences from one binary.
//
//   - Civilian: guided output, hidden prompt on set, friendly errors that
//     always end with the next command to run.
//   - AXI (agent interface): --json on every command, a distinct exit code
//     per outcome, secret on stdin, no TTY required.
//
// The CLI adds no secret-handling code of its own — every read/write/delete
// goes through keyring.Store, inheriting the library's guarantees: secret
// never on argv, read-back verify on writes, printable-ASCII contract,
// strict not-found vs unreadable classification.
//
// Design: kr-7i3.6 (~/Projects/dk/Project/keyring/plans/keyring-cli-design.md).
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"maps"
	"os"
	"strings"
	"time"

	"github.com/dkoosis/keyring"
	"golang.org/x/term"
)

// Exit codes, one per outcome, stable for agents (design §3.2). Codes 3–7
// map 1:1 to the library sentinels so an agent switches on the code without
// parsing prose.
const (
	exitOK             = 0
	exitGeneric        = 1
	exitValidation     = 2
	exitNotFound       = 3
	exitUnreadable     = 4
	exitVerifyFailed   = 5
	exitExists         = 6
	exitUnsupported    = 7
	exitDoctorFindings = 8 // reserved for `doctor` (kr-7i3.2)
)

// codeNames maps exit codes to the stable string carried in every --json
// envelope's "code" field.
var codeNames = map[int]string{
	exitOK:             "ok",
	exitGeneric:        "generic",
	exitValidation:     "validation",
	exitNotFound:       "not_found",
	exitUnreadable:     "unreadable",
	exitVerifyFailed:   "verify_failed",
	exitExists:         "exists",
	exitUnsupported:    "unsupported",
	exitDoctorFindings: "doctor_findings",
}

// app carries the process boundary as injectable seams so tests drive every
// command without a real TTY, stdin, or /usr/bin/security.
type app struct {
	stdin       io.Reader
	stdout      io.Writer
	stderr      io.Writer
	stdinTTY    bool
	stdoutTTY   bool
	securityBin string                              // test seam; empty = library default
	readSecret  func(prompt string) (string, error) // hidden-prompt seam
}

func main() {
	a := &app{
		stdin:      os.Stdin,
		stdout:     os.Stdout,
		stderr:     os.Stderr,
		stdinTTY:   term.IsTerminal(int(os.Stdin.Fd())),
		stdoutTTY:  term.IsTerminal(int(os.Stdout.Fd())),
		readSecret: readSecretFromTTY,
	}
	os.Exit(a.run(os.Args[1:]))
}

// readSecretFromTTY reads a secret with echo off, from /dev/tty — never
// stdin, so a piped stdin still means agent mode (design §2).
func readSecretFromTTY(prompt string) (string, error) {
	tty, err := os.Open("/dev/tty")
	if err != nil {
		return "", fmt.Errorf("opening /dev/tty for the hidden prompt: %w", err)
	}
	defer tty.Close()
	fmt.Fprint(os.Stderr, prompt)
	b, err := term.ReadPassword(int(tty.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

const usageText = `keyring — macOS keychain items, without remembering security(1)

usage:
  keyring set <service> <account>   store a secret (hidden prompt, or stdin when piped)
  keyring get <service> <account>   read a secret (masked on a terminal; --raw reveals)
  keyring ls  <service>             list items under a service (never prints values)
  keyring rm  <service> <account>   delete an item (confirms; --yes to skip)

global flags: --json  --keychain <abs-path>  --timeout <duration>
set flags:    --stdin  --force        get flags: --raw        rm flags: --yes

exit codes: 0 ok · 2 validation · 3 not found · 4 unreadable/locked ·
            5 verify failed · 6 already exists · 7 unsupported/disabled
`

func (a *app) run(args []string) int {
	if len(args) == 0 {
		fmt.Fprint(a.stderr, usageText)
		return exitValidation
	}
	cmd, rest := args[0], args[1:]
	switch cmd {
	case "set":
		return a.cmdSet(rest)
	case "get":
		return a.cmdGet(rest)
	case "ls":
		return a.cmdLs(rest)
	case "rm":
		return a.cmdRm(rest)
	case "-h", "--help", "help":
		fmt.Fprint(a.stdout, usageText)
		return exitOK
	default:
		fmt.Fprintf(a.stderr, "keyring: unknown command %q\n\n%s", cmd, usageText)
		return exitValidation
	}
}

// common holds the flags every command shares plus the positional
// service/account pair once parsed.
type common struct {
	jsonOut  bool
	keychain string
	timeout  time.Duration
	service  string
	account  string
}

// newFlagSet builds a FlagSet with the shared flags wired into c.
func (a *app) newFlagSet(name string, c *common) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(a.stderr)
	fs.BoolVar(&c.jsonOut, "json", false, "machine-readable output")
	fs.StringVar(&c.keychain, "keychain", "", "absolute path to a specific keychain file")
	fs.DurationVar(&c.timeout, "timeout", 0, "per-invocation timeout (default 10s)")
	return fs
}

// store opens the keyring.Store for c, honoring the shared flags and the
// test seam.
func (a *app) store(c *common) (*keyring.Store, error) {
	return keyring.New(c.service, a.storeOpts(c)...)
}

func (a *app) storeOpts(c *common) []keyring.Option {
	var opts []keyring.Option
	if c.keychain != "" {
		opts = append(opts, keyring.WithKeychain(c.keychain))
	}
	if c.timeout > 0 {
		opts = append(opts, keyring.WithTimeout(c.timeout))
	}
	if a.securityBin != "" {
		opts = append(opts, keyring.WithSecurityBin(a.securityBin))
	}
	return opts
}

// parseInterspersed parses args allowing flags before AND after the
// positionals (`keyring get svc acct --json` must work — agents append
// flags), which stdlib flag alone does not: it stops at the first
// non-flag argument. Each positional is collected and parsing resumes on
// the remainder.
func parseInterspersed(fs *flag.FlagSet, args []string) ([]string, error) {
	var pos []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		rest := fs.Args()
		if len(rest) == 0 {
			return pos, nil
		}
		pos = append(pos, rest[0])
		args = rest[1:]
	}
}

// positionals validates the service/account arguments.
func positionals(args []string, c *common, wantAccount bool) error {
	want := 2
	if !wantAccount {
		want = 1
	}
	if len(args) != want {
		if wantAccount {
			return fmt.Errorf("expected <service> <account>, got %d argument(s)", len(args))
		}
		return fmt.Errorf("expected <service>, got %d argument(s)", len(args))
	}
	c.service = args[0]
	if wantAccount {
		c.account = args[1]
	}
	return nil
}

// exitCodeFor maps a library error onto the stable exit-code table.
func exitCodeFor(err error) int {
	switch {
	case err == nil:
		return exitOK
	case errors.Is(err, keyring.ErrNotFound):
		return exitNotFound
	case errors.Is(err, keyring.ErrUnreadable):
		return exitUnreadable
	case errors.Is(err, keyring.ErrVerifyFailed):
		return exitVerifyFailed
	case errors.Is(err, keyring.ErrExists):
		return exitExists
	case errors.Is(err, keyring.ErrUnsupported):
		return exitUnsupported
	default:
		return exitGeneric
	}
}

// sentinelName is the --json "sentinel" field: the library sentinel behind
// an error, or "" when none applies.
func sentinelName(code int) string {
	switch code {
	case exitNotFound, exitUnreadable, exitVerifyFailed, exitExists, exitUnsupported:
		return codeNames[code]
	}
	return ""
}

// envVarFor is the conventional fallback env-var name used in error tails
// when no manifest supplies one: <APP>_<ACCOUNT>_API_KEY, uppercased,
// non-alphanumerics folded to underscores.
func envVarFor(service, account string) string {
	fold := func(s string) string {
		return strings.Map(func(r rune) rune {
			switch {
			case r >= 'a' && r <= 'z':
				return r - 32
			case r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
				return r
			default:
				return '_'
			}
		}, s)
	}
	return fold(service) + "_" + fold(account) + "_API_KEY"
}

// nextCommand is the load-bearing civilian rule: every failure ends with the
// next command to run (design §2).
func nextCommand(err error, service, account string) string {
	sa := service + " " + account
	switch {
	case errors.Is(err, keyring.ErrNotFound):
		return "→ store it: keyring set " + sa
	case errors.Is(err, keyring.ErrUnreadable):
		return "→ unlock the login keychain (Keychain Access → File → Unlock), then retry. Or bypass: export " + keyring.DisableEnv + "=1"
	case errors.Is(err, keyring.ErrVerifyFailed):
		return "→ indeterminate, not a failed write. Check: keyring get " + sa
	case errors.Is(err, keyring.ErrExists):
		return "→ overwrite intentionally: keyring set " + sa + " --force"
	case errors.Is(err, keyring.ErrUnsupported):
		return "→ no keychain here; use the env var " + envVarFor(service, account)
	}
	return ""
}

// envelope is the shared --json shape (design §3.3): ok and code on every
// object; error/sentinel only on failures; per-command fields via extra.
type envelope struct {
	OK      bool   `json:"ok"`
	Code    string `json:"code"`
	Command string `json:"command"`
	Service string `json:"service,omitempty"`
	Account string `json:"account,omitempty"`
	Error   string `json:"error,omitempty"`
	// Sentinel distinguishes "which library sentinel" from the exit name;
	// null (omitted) when no sentinel applies.
	Sentinel string `json:"sentinel,omitempty"`
}

// emitJSON writes one JSON object to stdout: the envelope merged with the
// per-command fields in extra.
func (a *app) emitJSON(env envelope, extra map[string]any) {
	m := map[string]any{
		"ok":      env.OK,
		"code":    env.Code,
		"command": env.Command,
	}
	if env.Service != "" {
		m["service"] = env.Service
	}
	if env.Account != "" {
		m["account"] = env.Account
	}
	if env.Error != "" {
		m["error"] = env.Error
	}
	if env.Sentinel != "" {
		m["sentinel"] = env.Sentinel
	}
	maps.Copy(m, extra)
	enc := json.NewEncoder(a.stdout)
	_ = enc.Encode(m)
}

// fail reports one failure in the requested mode and returns its exit code.
// msg must already end with the next-command tail where one exists.
func (a *app) fail(c *common, command string, code int, msg string) int {
	if c.jsonOut {
		a.emitJSON(envelope{
			OK: false, Code: codeNames[code], Command: command,
			Service: c.service, Account: c.account,
			Error: msg, Sentinel: sentinelName(code),
		}, nil)
	} else {
		fmt.Fprintf(a.stderr, "keyring %s: %s\n", command, msg)
	}
	return code
}

// failErr maps a library error to its exit code and message (with the
// civilian next-command tail appended) and reports it.
func (a *app) failErr(c *common, command string, err error) int {
	code := exitCodeFor(err)
	msg := err.Error()
	if tail := nextCommand(err, c.service, c.account); tail != "" {
		msg += "\n  " + tail
	}
	return a.fail(c, command, code, msg)
}

// confirm asks a y/N question on the terminal, defaulting to No. In agent
// mode (stdin not a TTY) an unconfirmed destructive action fails closed —
// callers must check c and --yes before getting here.
func (a *app) confirm(prompt string) bool {
	fmt.Fprintf(a.stderr, "%s [y/N] ", prompt)
	line, err := bufio.NewReader(a.stdin).ReadString('\n')
	if err != nil && line == "" {
		return false
	}
	answer := strings.ToLower(strings.TrimSpace(line))
	return answer == "y" || answer == "yes"
}

// ── set ────────────────────────────────────────────────────────────────────

func (a *app) cmdSet(args []string) int {
	var c common
	var useStdin, force bool
	fs := a.newFlagSet("set", &c)
	fs.BoolVar(&useStdin, "stdin", false, "read the value from stdin (auto when stdin is not a terminal)")
	fs.BoolVar(&force, "force", false, "overwrite an existing item")
	pos, err := parseInterspersed(fs, args)
	if err != nil {
		return exitValidation
	}
	if err := positionals(pos, &c, true); err != nil {
		return a.fail(&c, "set", exitValidation, err.Error()+"\n  → keyring set <service> <account>")
	}

	value, stripped, err := a.readValue(useStdin, c.service, c.account)
	if err != nil {
		return a.fail(&c, "set", exitGeneric, err.Error())
	}
	if value == "" {
		return a.fail(&c, "set", exitValidation, "value is empty\n  → pipe it in: printf %s \"$KEY\" | keyring set "+c.service+" "+c.account+" --stdin")
	}
	if code := a.prevalidate(&c, value); code != exitOK {
		return code
	}

	s, err := a.store(&c)
	if err != nil {
		return a.fail(&c, "set", exitValidation, err.Error())
	}
	if force {
		err = s.Set(c.account, value)
	} else {
		err = s.SetIfAbsent(c.account, value)
	}
	if err != nil {
		return a.failErr(&c, "set", err)
	}

	if c.jsonOut {
		a.emitJSON(envelope{OK: true, Code: "ok", Command: "set", Service: c.service, Account: c.account}, map[string]any{
			"bytes": len(value), "verified": true, "stripped_trailing_newline": stripped,
		})
		return exitOK
	}
	if stripped {
		fmt.Fprintln(a.stderr, "note: stripped a trailing newline")
	}
	fmt.Fprintf(a.stdout, "✓ stored %s/%s (%d bytes) — verified by read-back\n", c.service, c.account, len(value))
	return exitOK
}

// readValue reads the secret: stdin in agent mode (piped stdin or --stdin),
// hidden prompt otherwise. It strips one trailing newline — the #1 silent
// bug is a key pasted or piped with one — and reports whether it did.
func (a *app) readValue(useStdin bool, service, account string) (value string, stripped bool, err error) {
	if useStdin || !a.stdinTTY {
		b, err := io.ReadAll(a.stdin)
		if err != nil {
			return "", false, fmt.Errorf("reading value from stdin: %w", err)
		}
		value = string(b)
	} else {
		value, err = a.readSecret(fmt.Sprintf("Enter value for %s/%s (input hidden): ", service, account))
		if err != nil {
			return "", false, err
		}
	}
	switch {
	case strings.HasSuffix(value, "\r\n"):
		return strings.TrimSuffix(value, "\r\n"), true, nil
	case strings.HasSuffix(value, "\n"):
		return strings.TrimSuffix(value, "\n"), true, nil
	}
	return value, false, nil
}

// prevalidate runs the printable-ASCII check before writing so the failure
// is friendly: position and class only — never the offending byte of a
// secret (mirrors the library's printableASCIIOnlySecret rule).
func (a *app) prevalidate(c *common, value string) int {
	for i, r := range value {
		if r < 0x20 || r > 0x7e {
			class := "non-ASCII"
			if r < 0x20 || r == 0x7f {
				class = "non-printable (0x00–0x1f)"
			}
			return a.fail(c, "set", exitValidation, fmt.Sprintf(
				"byte %d of the value is %s — the keychain silently corrupts such values on read-back\n  → if this is a PEM key or has accents, base64-encode it first: base64 | keyring set %s %s --stdin",
				i, class, c.service, c.account))
		}
	}
	return exitOK
}

// ── get ────────────────────────────────────────────────────────────────────

func (a *app) cmdGet(args []string) int {
	var c common
	var raw bool
	fs := a.newFlagSet("get", &c)
	fs.BoolVar(&raw, "raw", false, "print the full value on a terminal (default is masked)")
	pos, err := parseInterspersed(fs, args)
	if err != nil {
		return exitValidation
	}
	if err := positionals(pos, &c, true); err != nil {
		return a.fail(&c, "get", exitValidation, err.Error()+"\n  → keyring get <service> <account>")
	}
	s, err := a.store(&c)
	if err != nil {
		return a.fail(&c, "get", exitValidation, err.Error())
	}
	value, err := s.Get(c.account)
	if err != nil {
		return a.failErr(&c, "get", err)
	}
	switch {
	case c.jsonOut:
		a.emitJSON(envelope{OK: true, Code: "ok", Command: "get", Service: c.service, Account: c.account},
			map[string]any{"value": value})
	case a.stdoutTTY && !raw:
		// Masked receipt on a terminal (ratified kr-7i3.6 §7.2): confirm the
		// value exists and its shape without splashing it into scrollback.
		fmt.Fprintf(a.stdout, "%s/%s = %s (%d bytes)\n", c.service, c.account, mask(value), len(value))
		fmt.Fprintln(a.stderr, "note: masked — add --raw to reveal, or pipe to another command for the plain value")
	default:
		// Piped (agent) or --raw: the value and nothing else.
		fmt.Fprintln(a.stdout, value)
	}
	return exitOK
}

// mask keeps just enough prefix to recognize a credential: 4 chars + …, or
// all-masked when the value is too short to safely preview.
func mask(v string) string {
	if len(v) <= 8 {
		return "…"
	}
	return v[:4] + "…"
}

// ── ls ─────────────────────────────────────────────────────────────────────

func (a *app) cmdLs(args []string) int {
	var c common
	fs := a.newFlagSet("ls", &c)
	pos, err := parseInterspersed(fs, args)
	if err != nil {
		return exitValidation
	}
	if err := positionals(pos, &c, false); err != nil {
		return a.fail(&c, "ls", exitValidation, err.Error()+"\n  → keyring ls <service>")
	}
	s, err := a.store(&c)
	if err != nil {
		return a.fail(&c, "ls", exitValidation, err.Error())
	}
	ctx := context.Background()
	items, err := s.List(ctx)
	if err != nil {
		return a.failErr(&c, "ls", err)
	}
	// Duplicate detection scans the whole search list regardless of a pinned
	// keychain — that ambiguity is exactly what it exists to expose.
	dup := map[string]bool{}
	if groups, err := keyring.DumpDuplicates(ctx, c.service, a.storeOpts(&c)...); err == nil {
		for _, g := range groups {
			dup[g.Account] = true
		}
	}

	type lsItem struct {
		Service         string `json:"service"`
		Account         string `json:"account"`
		Keychain        string `json:"keychain"`
		Duplicate       bool   `json:"duplicate"`
		TrailingNewline bool   `json:"trailing_newline"`
	}
	out := make([]lsItem, 0, len(items))
	for _, it := range items {
		// Trailing-newline sniff: reads the value only to classify its last
		// byte; the bytes never reach any output. A failed read just means
		// "unknown", reported as false — ls inventories, doctor judges.
		trailing := false
		if v, err := s.Get(it.Account); err == nil {
			trailing = strings.HasSuffix(v, "\n")
		}
		out = append(out, lsItem{
			Service: c.service, Account: it.Account, Keychain: it.Keychain,
			Duplicate: dup[it.Account], TrailingNewline: trailing,
		})
	}

	if c.jsonOut {
		a.emitJSON(envelope{OK: true, Code: "ok", Command: "ls", Service: c.service},
			map[string]any{"items": out})
		return exitOK
	}
	if len(out) == 0 {
		fmt.Fprintf(a.stdout, "no items under service %q\n", c.service)
		return exitOK
	}
	for _, it := range out {
		flags := ""
		if it.Duplicate {
			flags += "  ⚠ duplicate"
		}
		if it.TrailingNewline {
			flags += "  ⚠ trailing-newline"
		}
		fmt.Fprintf(a.stdout, "%s/%s  %s%s\n", it.Service, it.Account, it.Keychain, flags)
	}
	return exitOK
}

// ── rm ─────────────────────────────────────────────────────────────────────

func (a *app) cmdRm(args []string) int {
	var c common
	var yes bool
	fs := a.newFlagSet("rm", &c)
	fs.BoolVar(&yes, "yes", false, "skip the confirmation (required when stdin is not a terminal)")
	pos, err := parseInterspersed(fs, args)
	if err != nil {
		return exitValidation
	}
	if err := positionals(pos, &c, true); err != nil {
		return a.fail(&c, "rm", exitValidation, err.Error()+"\n  → keyring rm <service> <account>")
	}
	if !yes {
		if !a.stdinTTY {
			// Fail closed: an unconfirmed destructive action in agent mode
			// never auto-proceeds (design §3.1).
			return a.fail(&c, "rm", exitValidation, "refusing to delete without confirmation\n  → add --yes to delete non-interactively")
		}
		// Show the item — service/account/keychain, never the value.
		fmt.Fprintf(a.stderr, "item: %s/%s\n", c.service, c.account)
		if !a.confirm("Delete this item?") {
			fmt.Fprintln(a.stderr, "aborted — nothing deleted")
			return exitValidation
		}
	}
	s, err := a.store(&c)
	if err != nil {
		return a.fail(&c, "rm", exitValidation, err.Error())
	}
	if err := s.Delete(c.account); err != nil {
		return a.failErr(&c, "rm", err)
	}
	if c.jsonOut {
		a.emitJSON(envelope{OK: true, Code: "ok", Command: "rm", Service: c.service, Account: c.account},
			map[string]any{"deleted": true})
		return exitOK
	}
	fmt.Fprintf(a.stdout, "✓ deleted %s/%s\n", c.service, c.account)
	return exitOK
}
