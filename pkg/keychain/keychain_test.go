package keychain

import (
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// These run on every platform. The Keychain itself is macOS only, but the
// parsing and the argument construction are where the mistakes are, and a
// macOS-only test is one that runs when somebody happens to have a Mac.

// A dump in the shape security(1) prints: quoted values for ordinary text,
// hex for anything that does not survive quoting, <NULL> for absent.
const sampleDump = `keychain: "/Users/alice/Library/Keychains/login.keychain-db"
version: 512
class: "genp"
attributes:
    0x00000007 <blob>="GitHub"
    "acct"<blob>="alice"
    "labl"<blob>="GitHub"
    "svce"<blob>="github.com"
keychain: "/Users/alice/Library/Keychains/login.keychain-db"
version: 512
class: "genp"
attributes:
    "acct"<blob>=0x626F62  "bob"
    "labl"<blob>=<NULL>
    "svce"<blob>="gitlab.com"
keychain: "/Users/alice/Library/Keychains/login.keychain-db"
version: 512
class: "genp"
attributes:
    "acct"<blob>=<NULL>
    "svce"<blob>="no-account.example"
`

func TestParseDumpReadsServiceAndAccount(t *testing.T) {
	items := parseDump([]byte(sampleDump))
	require.Len(t, items, 3)

	assert.Equal(t, "github.com", items[0].Service)
	assert.Equal(t, "alice", items[0].Account)
	assert.Equal(t, "GitHub", items[0].Label)

	// The hex form has to be read too: it is what security(1) falls back to,
	// and skipping those items would silently import half a keychain.
	assert.Equal(t, "gitlab.com", items[1].Service)
	assert.Equal(t, "bob", items[1].Account)
	assert.Empty(t, items[1].Label, "<NULL> is an absent value, not the text NULL")

	assert.Equal(t, "no-account.example", items[2].Service)
	assert.Empty(t, items[2].Account)
}

func TestParseDumpSkipsRecordsWithoutAService(t *testing.T) {
	// An item with no service cannot be addressed by find-generic-password,
	// so importing it would produce an entry nothing can update.
	const dump = `keychain: "login.keychain-db"
attributes:
    "acct"<blob>="alice"
keychain: "login.keychain-db"
attributes:
    "svce"<blob>="real.example"
`
	items := parseDump([]byte(dump))
	require.Len(t, items, 1)
	assert.Equal(t, "real.example", items[0].Service)
}

func TestParseDumpOnJunk(t *testing.T) {
	for name, input := range map[string]string{
		"empty":         "",
		"not a dump":    "command not found\n",
		"header only":   "keychain: \"login.keychain-db\"\n",
		"no attributes": "keychain: \"login.keychain-db\"\nversion: 512\n",
	} {
		t.Run(name, func(t *testing.T) {
			assert.Empty(t, parseDump([]byte(input)))
		})
	}
}

func TestParseAttrLine(t *testing.T) {
	for name, tc := range map[string]struct {
		line  string
		key   string
		value string
		ok    bool
	}{
		"quoted":      {`"svce"<blob>="github.com"`, "svce", "github.com", true},
		"null":        {`"labl"<blob>=<NULL>`, "labl", "", true},
		"hex":         {`"acct"<blob>=0x616C696365`, "acct", "alice", true},
		"hex quoted":  {`"acct"<blob>=0x616C696365  "alice"`, "acct", "alice", true},
		"numeric key": {`0x00000007 <blob>="GitHub"`, "", "", false},
		"no equals":   {`"svce"<blob>`, "", "", false},
		"junk":        {`nonsense`, "", "", false},
	} {
		t.Run(name, func(t *testing.T) {
			key, value, ok := parseAttrLine(tc.line)
			assert.Equal(t, tc.ok, ok)
			if tc.ok {
				assert.Equal(t, tc.key, key)
				assert.Equal(t, tc.value, value)
			}
		})
	}
}

func TestDecodeHex(t *testing.T) {
	got, err := decodeHex("0x616C696365")
	require.NoError(t, err)
	assert.Equal(t, "alice", got)

	_, err = decodeHex("0xZZ")
	assert.Error(t, err)

	_, err = decodeHex("0x616C6963657")
	assert.ErrorContains(t, err, "odd-length")
}

// TestAddArgsKeepThePasswordOffTheCommandLine: an argument is visible in ps
// to every process on the machine, so the secret goes in on stdin.
func TestAddArgsKeepThePasswordOffTheCommandLine(t *testing.T) {
	it := Item{Service: "github.com", Account: "alice", Label: "GitHub", Password: "hunter2"}
	args := addArgs(it)

	assert.Equal(t, "add-generic-password", args[0])
	assert.Contains(t, args, "-U", "storing twice must update rather than fail")
	assert.Contains(t, args, "-w", "-w takes the password on stdin")
	for _, a := range args {
		assert.NotContains(t, a, "hunter2", "the password must not appear in argv")
	}
}

func TestFindArgsAskForThePasswordAlone(t *testing.T) {
	args := findArgs("github.com", "alice")
	assert.Equal(t, "find-generic-password", args[0])
	assert.Contains(t, strings.Join(args, " "), "-s github.com")
	assert.Contains(t, strings.Join(args, " "), "-a alice")
	// -w prints the password by itself, which keeps parsing out of the path
	// that handles a secret.
	assert.Equal(t, "-w", args[len(args)-1])

	// Without an account the item is addressed by service alone.
	args = findArgs("github.com", "")
	assert.NotContains(t, args, "-a")
}

func TestDeleteArgs(t *testing.T) {
	assert.Equal(t, []string{"delete-generic-password", "-s", "github.com", "-a", "alice"},
		deleteArgs("github.com", "alice"))
	assert.Equal(t, []string{"delete-generic-password", "-s", "github.com"},
		deleteArgs("github.com", ""))
}

// TestClassifyErrorExplainsWhatToDo covers the three failures a user hits.
// security(1) reports them all as a non-zero status with the reason on
// stderr.
func TestClassifyErrorExplainsWhatToDo(t *testing.T) {
	for name, tc := range map[string]struct {
		output string
		want   string
		is     error
	}{
		"missing item": {
			output: "security: SecKeychainSearchCopyNext: The specified item could not be found in the keychain.",
			want:   "not found",
			is:     ErrNotFound,
		},
		"no prompt possible": {
			output: "security: SecKeychainItemCopyContent: User interaction is not allowed.",
			want:   "unlock-keychain",
			is:     ErrDenied,
		},
		"user dismissed": {
			output: "security: SecKeychainItemCopyContent: User canceled the operation.",
			want:   "dismissed",
			is:     ErrDenied,
		},
	} {
		t.Run(name, func(t *testing.T) {
			err := classifyError([]byte(tc.output), errors.New("exit status 44"))
			require.Error(t, err)
			assert.ErrorIs(t, err, tc.is)
			assert.Contains(t, err.Error(), tc.want)
		})
	}
}

func TestClassifyErrorWithNoOutput(t *testing.T) {
	err := classifyError(nil, errors.New("exit status 1"))
	assert.ErrorContains(t, err, "security")
	assert.ErrorContains(t, err, "exit status 1")
}

// TestStorePathIsUsableAsAnEntryName: Keychain services are free text and
// routinely contain slashes and spaces, which would otherwise become
// directories or an unaddressable entry.
func TestStorePathIsUsableAsAnEntryName(t *testing.T) {
	for name, tc := range map[string]struct {
		item Item
		want string
	}{
		"ordinary": {
			Item{Service: "github.com", Account: "alice"},
			"keychain/github.com/alice",
		},
		"no account": {
			Item{Service: "github.com"},
			"keychain/github.com",
		},
		"slash in service": {
			Item{Service: "https://example.com/login", Account: "alice"},
			"keychain/https:__example.com_login/alice",
		},
		"empty service": {
			Item{Account: "alice"},
			"keychain/unnamed/alice",
		},
		"leading dots": {
			Item{Service: "..", Account: "x"},
			"keychain/unnamed/x",
		},
	} {
		t.Run(name, func(t *testing.T) {
			got := StorePath("keychain", tc.item)
			assert.Equal(t, tc.want, got)
			// Whatever comes out must not climb out of the store.
			assert.NotContains(t, got, "/../")
			assert.False(t, strings.HasSuffix(got, "/.."))
		})
	}
}

// TestDumpArgsDoNotAskForSecrets: `dump-keychain -g` would prompt for every
// item in the keychain at once and put them all in one buffer. Listing names
// the items; the secrets are read individually, when the user has agreed to
// each.
func TestDumpArgsDoNotAskForSecrets(t *testing.T) {
	args := dumpArgs()
	assert.Equal(t, []string{"dump-keychain"}, args)
	assert.NotContains(t, args, "-g", "a listing must not decrypt anything")
}
