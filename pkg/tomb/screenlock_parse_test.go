package tomb

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// The samples below are the shape `ioreg -n Root -d1 -a` produces on macOS:
// a plist whose IOConsoleUsers array holds the session dictionary, with the
// lock state as one key among many.

const ioregLocked = `<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0">
<array><dict>
	<key>IOConsoleUsers</key>
	<array><dict>
		<key>kCGSSessionUserNameKey</key><string>alice</string>
		<key>CGSSessionScreenIsLocked</key><true/>
		<key>kCGSSessionOnConsoleKey</key><true/>
	</dict></array>
</dict></array>
</plist>`

const ioregUnlocked = `<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0">
<array><dict>
	<key>IOConsoleUsers</key>
	<array><dict>
		<key>kCGSSessionUserNameKey</key><string>alice</string>
		<key>CGSSessionScreenIsLocked</key><false/>
		<key>kCGSSessionOnConsoleKey</key><true/>
	</dict></array>
</dict></array>
</plist>`

// Before the screen is locked for the first time in a session the key is not
// published at all.
const ioregNeverLocked = `<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0">
<array><dict>
	<key>IOConsoleUsers</key>
	<array><dict>
		<key>kCGSSessionUserNameKey</key><string>alice</string>
		<key>kCGSSessionOnConsoleKey</key><true/>
	</dict></array>
</dict></array>
</plist>`

func TestParseScreenLocked(t *testing.T) {
	assert.True(t, parseScreenLocked([]byte(ioregLocked)))
	assert.False(t, parseScreenLocked([]byte(ioregUnlocked)))
	assert.False(t, parseScreenLocked([]byte(ioregNeverLocked)),
		"a key that was never published means the screen was never locked")
}

// TestParseScreenLockedFailsOpen: an unreadable or truncated answer must not
// be read as "locked". A tomb that closed itself because ioreg was killed
// mid-write would be a password manager that loses your session at random.
func TestParseScreenLockedFailsOpen(t *testing.T) {
	for name, input := range map[string]string{
		"empty":           "",
		"not a plist":     "command not found",
		"truncated":       `<key>CGSSessionScreenIsLocked</key>`,
		"key but no bool": `<key>CGSSessionScreenIsLocked</key><string>maybe</string>`,
	} {
		t.Run(name, func(t *testing.T) {
			assert.False(t, parseScreenLocked([]byte(input)))
		})
	}
}

// TestParseScreenLockedReadsTheNearestValue guards against matching a
// boolean belonging to a different key: the session dictionary holds several,
// and taking the wrong one inverts the answer.
func TestParseScreenLockedReadsTheNearestValue(t *testing.T) {
	// Locked, followed by another key whose value is false.
	locked := `<key>CGSSessionScreenIsLocked</key><true/>
	<key>kCGSSessionSecureInputPID</key><false/>`
	assert.True(t, parseScreenLocked([]byte(locked)))

	// Unlocked, followed by another key whose value is true.
	unlocked := `<key>CGSSessionScreenIsLocked</key><false/>
	<key>kCGSSessionOnConsoleKey</key><true/>`
	assert.False(t, parseScreenLocked([]byte(unlocked)))
}
