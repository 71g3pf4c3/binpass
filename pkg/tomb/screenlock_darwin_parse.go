package tomb

import "bytes"

// parseScreenLocked reads the lock state out of `ioreg -n Root -d1 -a`.
//
// The window server publishes it as CGSSessionScreenIsLocked in the console
// user's session dictionary. Kept separate from the code that runs ioreg so
// that it can be tested on any platform against captured output — the parser
// is the part that breaks, and a macOS-only test is one that runs when
// somebody happens to have a Mac.
func parseScreenLocked(ioregOutput []byte) bool {
	const key = "CGSSessionScreenIsLocked"

	i := bytes.Index(ioregOutput, []byte(key))
	if i < 0 {
		// Absent entirely when the screen has never been locked this
		// session, which is not the same as being unable to tell.
		return false
	}

	// The value follows the key in the plist as <true/> or <false/>, with
	// the key's own markup in between. Scanning forward to whichever comes
	// first avoids parsing the whole plist for one boolean.
	rest := ioregOutput[i+len(key):]
	t := bytes.Index(rest, []byte("<true/>"))
	f := bytes.Index(rest, []byte("<false/>"))

	switch {
	case t < 0:
		return false
	case f < 0:
		return true
	default:
		return t < f
	}
}
