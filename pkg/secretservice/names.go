package secretservice

import "errors"

// BusName is the well-known name a Secret Service provider owns. Only one
// process on a session bus can hold it, which is why `ss doctor` exists.
//
// Declared here rather than beside the D-Bus implementation because the CLI
// names it in messages on every platform, including the ones where the
// provider cannot run.
const BusName = "org.freedesktop.secrets"

// ErrNameTaken reports that another provider owns the bus name.
var ErrNameTaken = errors.New("secretservice: " + BusName + " is already owned")

// Takeover says what to do when the bus name is already owned.
type Takeover string

// The takeover modes.
const (
	// TakeoverRefuse fails rather than displacing another provider.
	TakeoverRefuse Takeover = "refuse"
	// TakeoverReplace takes the name, asking the current owner to yield.
	TakeoverReplace Takeover = "replace"
	// TakeoverWait queues for the name and starts when it is free.
	TakeoverWait Takeover = "wait"
)
