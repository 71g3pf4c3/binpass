package remote

import (
	"bytes"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// LockFileName is the advisory lock file a client places at the remote root
// while it synchronises. It starts with a dot, so IsStoreContent already
// keeps it out of listings and it never reaches the store or state.db.
const LockFileName = ".binpass.lock"

// DefaultLockTTL bounds how long a lock survives without renewal: a client
// killed mid-sync must not block every other device forever, and a TTL is the
// only recovery mechanism a lock file on object storage can have.
const DefaultLockTTL = 5 * time.Minute

// advisoryLock is the parsed content of the lock file. The format is three
// "key: value" lines so a human can read it with cat and act on it when a
// device died mid-sync.
type advisoryLock struct {
	// Device identifies the holder, so Unlock only removes its own lock and
	// error messages can name the machine to go and look at.
	Device string
	// TS is when the lock was taken, in RFC 3339 as reported by the holder.
	TS time.Time
	// TTL is how long the lock stays valid without being released.
	TTL time.Duration
}

// marshal renders the lock file content.
func (l advisoryLock) marshal() []byte {
	var b bytes.Buffer
	fmt.Fprintf(&b, "device:%s\nts:%s\nttl:%d\n",
		l.Device, l.TS.UTC().Format(time.RFC3339), int(l.TTL.Seconds()))
	return b.Bytes()
}

// parseAdvisoryLock reads lock file content. Unknown lines are ignored so a
// newer binpass can extend the format without older clients failing on it.
func parseAdvisoryLock(data []byte) (advisoryLock, error) {
	var l advisoryLock
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		key, value, found := strings.Cut(line, ":")
		if !found {
			continue
		}
		switch key {
		case "device":
			l.Device = value
		case "ts":
			ts, err := time.Parse(time.RFC3339, value)
			if err != nil {
				return advisoryLock{}, fmt.Errorf("remote: bad ts in %s: %w", LockFileName, err)
			}
			l.TS = ts
		case "ttl":
			secs, err := strconv.Atoi(value)
			if err != nil || secs < 0 {
				return advisoryLock{}, fmt.Errorf("remote: bad ttl in %s: %q", LockFileName, value)
			}
			l.TTL = time.Duration(secs) * time.Second
		}
	}
	if l.Device == "" || l.TS.IsZero() {
		return advisoryLock{}, fmt.Errorf("remote: incomplete %s", LockFileName)
	}
	if l.TTL == 0 {
		l.TTL = DefaultLockTTL
	}
	return l, nil
}

// stale reports whether the lock has outlived its TTL. A lock from a device
// whose clock runs ahead is held a little longer on this side, and one whose
// clock runs behind expires early; both are the price of not having a
// central clock, and the TTL is sized to make the skew irrelevant.
func (l advisoryLock) stale(now time.Time) bool {
	return l.TS.Add(l.TTL).Before(now)
}

// LockHeldError reports that another device holds the advisory lock.
type LockHeldError struct {
	// Remote is the name of the remote that is locked.
	Remote string
	// Lock is the lock that was found on it.
	Lock advisoryLock
}

// Error names the holder and when the lock expires, so the operator's next
// step is obvious without reading source: wait, or go to that device.
func (e *LockHeldError) Error() string {
	return fmt.Sprintf("remote %s is locked by device %q since %s; it expires at %s. "+
		"If that device is gone, wait for the expiry or delete %s from the remote.",
		e.Remote, e.Lock.Device, e.Lock.TS.Format(time.RFC3339),
		e.Lock.TS.Add(e.Lock.TTL).Format(time.RFC3339), LockFileName)
}
