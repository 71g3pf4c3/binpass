// Package keychain moves secrets between the password store and the macOS
// Keychain.
//
// On macOS the system keystore cannot be replaced the way it can on Linux —
// there is no bus name to take over — so binpass integrates with it instead:
// import what is already in the Keychain, export what should also be there,
// and keep the two in step.
//
// Everything goes through the security(1) command line tool rather than the
// Security framework. Linking the framework would mean CGO, and CGO would
// cost the statically linked cross-compiled binary the project ships
// everywhere else (ARCHITECTURE.md §7.3). security(1) is present on every
// macOS install and its output is stable.
package keychain

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// Item is one Keychain generic password.
type Item struct {
	// Service is the item's service attribute, which is what most programs
	// key on. It becomes the store path when importing.
	Service string
	// Account is the user name the item belongs to.
	Account string
	// Label is the display name shown in Keychain Access.
	Label string
	// Password is the secret itself. It is empty in a listing: security(1)
	// only reveals it when asked for one item at a time.
	Password string
}

// ErrNotFound reports an item the Keychain does not hold.
var ErrNotFound = errors.New("keychain: item not found")

// ErrDenied reports that the user refused, or was not asked in time.
var ErrDenied = errors.New("keychain: access denied")

// findArgs builds the security(1) invocation that reads one generic
// password, secret included.
//
// -w prints the password alone, which keeps parsing out of the path that
// handles a secret.
func findArgs(service, account string) []string {
	args := []string{"find-generic-password", "-s", service}
	if account != "" {
		args = append(args, "-a", account)
	}
	return append(args, "-w")
}

// dumpArgs builds the invocation that lists every generic password.
//
// The secrets are deliberately not included: a dump with -g would prompt for
// every item and put the whole Keychain in one buffer. Import reads each
// secret separately, when the user has agreed to it.
func dumpArgs() []string {
	return []string{"dump-keychain"}
}

// addArgs builds the invocation that stores an item.
//
// -U updates an existing item rather than failing, and -w takes the password
// on stdin. Passing it as an argument would publish the secret in ps to
// every process on the machine.
func addArgs(it Item) []string {
	args := []string{"add-generic-password", "-s", it.Service, "-U"}
	if it.Account != "" {
		args = append(args, "-a", it.Account)
	}
	if it.Label != "" {
		args = append(args, "-l", it.Label)
	}
	return append(args, "-w")
}

// deleteArgs builds the invocation that removes an item.
func deleteArgs(service, account string) []string {
	args := []string{"delete-generic-password", "-s", service}
	if account != "" {
		args = append(args, "-a", account)
	}
	return args
}

// classifyError turns security(1)'s exit status into something actionable.
//
// It reports a missing item, a refused prompt and a locked keychain all as a
// non-zero status with the detail on stderr, so passing the status through
// leaves the user with a number and no idea whether to unlock something or
// to look for a typo.
func classifyError(out []byte, err error) error {
	text := strings.ToLower(string(out))
	switch {
	case strings.Contains(text, "could not be found"),
		strings.Contains(text, "the specified item could not be found"):
		return fmt.Errorf("%w: %s", ErrNotFound, firstLine(out))
	case strings.Contains(text, "user interaction is not allowed"):
		return fmt.Errorf("%w: the keychain needs a prompt, and none can be shown; "+
			"unlock it first with `security unlock-keychain`", ErrDenied)
	case strings.Contains(text, "user canceled"), strings.Contains(text, "user cancelled"):
		return fmt.Errorf("%w: the prompt was dismissed", ErrDenied)
	case strings.Contains(text, "authorization"), strings.Contains(text, "denied"):
		return fmt.Errorf("%w: %s", ErrDenied, firstLine(out))
	}
	if len(out) == 0 {
		return fmt.Errorf("keychain: security: %w", err)
	}
	return fmt.Errorf("keychain: security: %w: %s", err, firstLine(out))
}

// parseDump reads the items out of `security dump-keychain`.
//
// The format is one record per item, each a block of attributes, with the
// interesting ones being svce (service) and acct (account). Values are
// printed either as a quoted string or, when they contain anything unusual,
// as hex — both forms appear in one dump, so both have to be read.
func parseDump(out []byte) []Item {
	var items []Item
	var current Item
	inItem := false

	for _, line := range strings.Split(string(out), "\n") {
		trimmed := strings.TrimSpace(line)

		if strings.HasPrefix(trimmed, "keychain:") {
			// A new record begins. Emit whatever the previous one was, if
			// it named a service: an item without one cannot be addressed.
			if inItem && current.Service != "" {
				items = append(items, current)
			}
			current = Item{}
			inItem = true
			continue
		}
		if !inItem {
			continue
		}

		key, value, ok := parseAttrLine(trimmed)
		if !ok {
			continue
		}
		switch key {
		case "svce":
			current.Service = value
		case "acct":
			current.Account = value
		case "labl":
			current.Label = value
		}
	}
	if inItem && current.Service != "" {
		items = append(items, current)
	}
	return items
}

// parseAttrLine reads one attribute line from a dump.
//
// The shape is:
//
//	"svce"<blob>="GitHub"
//	"acct"<blob>=0x616C696365  "alice"
//	"labl"<blob>=<NULL>
func parseAttrLine(line string) (key, value string, ok bool) {
	if !strings.HasPrefix(line, `"`) {
		return "", "", false
	}
	end := strings.Index(line[1:], `"`)
	if end < 0 {
		return "", "", false
	}
	key = line[1 : end+1]

	eq := strings.Index(line, "=")
	if eq < 0 {
		return "", "", false
	}
	rest := strings.TrimSpace(line[eq+1:])

	switch {
	case rest == "<NULL>", rest == "":
		return key, "", true
	case strings.HasPrefix(rest, `"`):
		// A quoted string, possibly with a trailing comment.
		closing := strings.LastIndex(rest, `"`)
		if closing <= 0 {
			return "", "", false
		}
		return key, rest[1:closing], true
	case strings.HasPrefix(rest, "0x"):
		// Hex, sometimes followed by the same value quoted. The quoted form
		// is what a person wrote, so prefer it when present.
		if i := strings.Index(rest, `"`); i >= 0 {
			closing := strings.LastIndex(rest, `"`)
			if closing > i {
				return key, rest[i+1 : closing], true
			}
		}
		decoded, err := decodeHex(strings.Fields(rest)[0])
		if err != nil {
			return "", "", false
		}
		return key, decoded, true
	default:
		return key, rest, true
	}
}

// decodeHex decodes the 0x-prefixed form security(1) uses for values that do
// not survive quoting.
func decodeHex(s string) (string, error) {
	s = strings.TrimPrefix(s, "0x")
	if len(s)%2 != 0 {
		return "", fmt.Errorf("keychain: odd-length hex value %q", s)
	}
	out := make([]byte, 0, len(s)/2)
	for i := 0; i < len(s); i += 2 {
		b, err := strconv.ParseUint(s[i:i+2], 16, 8)
		if err != nil {
			return "", fmt.Errorf("keychain: bad hex value %q: %w", s, err)
		}
		out = append(out, byte(b))
	}
	return string(out), nil
}

// firstLine returns the first non-empty line of output, which is where
// security(1) puts the reason.
func firstLine(out []byte) string {
	for _, line := range strings.Split(string(out), "\n") {
		if s := strings.TrimSpace(line); s != "" {
			return s
		}
	}
	return ""
}

// StorePath returns the store path an item is imported to.
//
// Keychain items are keyed by service and account, which map naturally onto
// the directory-and-name layout pass already uses. Anything that cannot
// appear in a path is replaced rather than dropped, so two items cannot
// collapse onto one entry silently.
func StorePath(prefix string, it Item) string {
	service := sanitisePathComponent(it.Service)
	if service == "" {
		service = "unnamed"
	}
	parts := []string{prefix, service}
	if account := sanitisePathComponent(it.Account); account != "" {
		parts = append(parts, account)
	}
	return strings.Join(parts, "/")
}

// sanitisePathComponent makes a Keychain attribute usable as one path
// element.
func sanitisePathComponent(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch r {
		case '/', '\\', 0:
			b.WriteRune('_')
		default:
			if r < 0x20 {
				b.WriteRune('_')
				continue
			}
			b.WriteRune(r)
		}
	}
	return strings.Trim(strings.TrimSpace(b.String()), ".")
}
