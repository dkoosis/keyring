//go:build darwin

package keyring

import (
	"context"
	"strings"
	"testing"
)

// dumpFixture is realistic `security dump-keychain` output: two keychains,
// a duplicate (keyring-test, anthropic) pair across them, a singleton
// account, another service's item, an inet-class item, and a record whose
// acct is <NULL> — the parser must keep exactly the genp items with both
// svce and acct populated.
const dumpFixture = `keychain: "/Users/x/Library/Keychains/login.keychain-db"
version: 512
class: "genp"
attributes:
    0x00000007 <blob>="keyring-test"
    "acct"<blob>="anthropic"
    "svce"<blob>="keyring-test"
data:
keychain: "/Users/x/Library/Keychains/login.keychain-db"
version: 512
class: "genp"
attributes:
    "acct"<blob>="github"
    "svce"<blob>="keyring-test"
keychain: "/Users/x/Library/Keychains/login.keychain-db"
version: 512
class: "genp"
attributes:
    "acct"<blob>="anthropic"
    "svce"<blob>="other-app"
keychain: "/Users/x/Library/Keychains/login.keychain-db"
version: 512
class: "inet"
attributes:
    "acct"<blob>="anthropic"
    "svce"<blob>="keyring-test"
keychain: "/Users/x/Library/Keychains/login.keychain-db"
version: 512
class: "genp"
attributes:
    "acct"<NULL>
    "svce"<blob>="keyring-test"
keychain: "/Library/Keychains/System.keychain"
version: 512
class: "genp"
attributes:
    "acct"<blob>="anthropic"
    "svce"<blob>="keyring-test"
`

// stubDump returns a stub whose dump-keychain output is dumpFixture.
func stubDump(t *testing.T) (bin, dir string) {
	t.Helper()
	return stubSecurity(t, "cat <<'FIXTURE'\n"+dumpFixture+"FIXTURE\n")
}

func TestList_UsesDumpKeychainWithoutSecretFlags(t *testing.T) {
	bin, dir := stubDump(t)
	s := newTestStore(t, bin)
	items, err := s.List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	argv := readCapture(t, dir, "argv")
	if !strings.Contains(argv, "dump-keychain") {
		t.Errorf("argv missing dump-keychain: %q", argv)
	}
	for _, forbidden := range []string{"-w", "-d", "-g"} {
		if strings.Contains(argv, forbidden) {
			t.Errorf("argv contains secret-reading flag %s: %q", forbidden, argv)
		}
	}
	// 3 items under keyring-test: anthropic ×2 (two keychains) + github.
	// other-app, the inet item, and the NULL-account record are excluded.
	if len(items) != 3 {
		t.Fatalf("want 3 items, got %d: %+v", len(items), items)
	}
	byAccount := map[string]int{}
	for _, it := range items {
		byAccount[it.Account]++
		if it.Keychain == "" {
			t.Errorf("item %q missing keychain path", it.Account)
		}
	}
	if byAccount["anthropic"] != 2 || byAccount["github"] != 1 {
		t.Errorf("account distribution wrong: %v", byAccount)
	}
}

func TestList_PinnedKeychainReachesDumpKeychain(t *testing.T) {
	bin, dir := stubDump(t)
	s, err := New("keyring-test", WithKeychain("/tmp/pinned.keychain-db"))
	if err != nil {
		t.Fatal(err)
	}
	s.securityBin = bin
	if _, err := s.List(context.Background()); err != nil {
		t.Fatal(err)
	}
	if argv := readCapture(t, dir, "argv"); !strings.Contains(argv, "/tmp/pinned.keychain-db") {
		t.Errorf("pinned keychain missing from argv: %q", argv)
	}
}

func TestDumpDuplicates_GroupsOnlyRealDuplicates(t *testing.T) {
	bin, _ := stubDump(t)
	groups, err := DumpDuplicates(context.Background(), "keyring-test", WithSecurityBin(bin))
	if err != nil {
		t.Fatal(err)
	}
	if len(groups) != 1 {
		t.Fatalf("want 1 duplicate group, got %d: %+v", len(groups), groups)
	}
	g := groups[0]
	if g.Service != "keyring-test" || g.Account != "anthropic" || len(g.Items) != 2 {
		t.Fatalf("wrong group: %+v", g)
	}
	// The two hits live in different keychain files — that's the ambiguity.
	if g.Items[0].Keychain == g.Items[1].Keychain {
		t.Errorf("expected distinct keychains, both %q", g.Items[0].Keychain)
	}
}

func TestDumpDuplicates_IgnoresPinnedKeychain(t *testing.T) {
	bin, dir := stubDump(t)
	if _, err := DumpDuplicates(context.Background(), "keyring-test",
		WithSecurityBin(bin), WithKeychain("/tmp/pinned.keychain-db")); err != nil {
		t.Fatal(err)
	}
	// Duplicate detection must ALWAYS scan the whole search list; a pinned
	// keychain would hide the cross-keychain duplicates it exists to find.
	if argv := readCapture(t, dir, "argv"); strings.Contains(argv, "pinned.keychain-db") {
		t.Errorf("pinned keychain leaked into dump-keychain argv: %q", argv)
	}
}

func TestList_DumpFailureIsUnreadable(t *testing.T) {
	bin, _ := stubSecurity(t, "exit 51\n")
	s := newTestStore(t, bin)
	if _, err := s.List(context.Background()); err == nil {
		t.Fatal("want error, got nil")
	} else if !strings.Contains(err.Error(), ErrUnreadable.Error()) {
		t.Errorf("want ErrUnreadable, got %v", err)
	}
}
