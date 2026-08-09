package sync

import (
	"encoding/json"
	"sort"
)

// DeviceID identifies a single binpass installation in the sync mesh. It is
// typically the hostname but can be any unique string; the only requirement is
// that two devices that might edit the same file concurrently must have
// distinct IDs.
type DeviceID string

// VersionVector tracks the causal history of a single file across devices. Each
// device that has modified the file holds a monotonically increasing counter;
// the union of all (device, counter) pairs describes the set of events that
// produced the current version.
//
// Two vectors are compared to determine whether one version causally
// dominates the other or whether they have diverged and need conflict
// resolution (§8.5).
//
// The zero value is a valid empty vector. All methods treat a missing entry as
// having counter 0.
type VersionVector map[DeviceID]uint64

// Equal reports whether a and b describe the same causal history.
func (a VersionVector) Equal(b VersionVector) bool {
	for id, ca := range a {
		if cb, ok := b[id]; !ok && ca != 0 || ok && cb != ca {
			return false
		}
	}
	for id, cb := range b {
		if ca, ok := a[id]; !ok && cb != 0 || ok && ca != cb {
			return false
		}
	}
	return true
}

// Dominates reports whether a causally dominates b: every counter in a is
// greater than or equal to the corresponding counter in b, and at least one
// counter is strictly greater. A dominates B means A reflects all the events
// that B does, plus at least one more.
func (a VersionVector) Dominates(b VersionVector) bool {
	hasStrictlyGreater := false
	for id, ca := range a {
		cb, ok := b[id]
		if !ok {
			cb = 0
		}
		if ca < cb {
			return false
		}
		if ca > cb {
			hasStrictlyGreater = true
		}
	}
	// Check devices present in b but not in a: their counter is 0 in a,
	// so if b has a non-zero counter, a cannot dominate.
	for id, cb := range b {
		if _, ok := a[id]; !ok && cb > 0 {
			return false
		}
	}
	return hasStrictlyGreater
}

// Merge returns the pointwise maximum of a and b. The result subsumes both
// inputs: it dominates (or equals) each of them. This is the version vector
// stored after a successful sync.
func (a VersionVector) Merge(b VersionVector) VersionVector {
	out := a.Clone()
	for id, cb := range b {
		if ca, ok := out[id]; !ok || cb > ca {
			out[id] = cb
		}
	}
	return out
}

// Increment returns a copy of the vector with the counter for device
// incremented by delta. If the device is not present, it is added with
// counter delta.
func (a VersionVector) Increment(device DeviceID, delta uint64) VersionVector {
	out := a.Clone()
	out[device] += delta
	return out
}

// Clone returns a deep copy of the vector.
func (a VersionVector) Clone() VersionVector {
	if a == nil {
		return VersionVector{}
	}
	out := make(VersionVector, len(a))
	for id, c := range a {
		out[id] = c
	}
	return out
}

// IsEmpty reports whether the vector has no non-zero entries.
func (a VersionVector) IsEmpty() bool {
	for _, c := range a {
		if c != 0 {
			return false
		}
	}
	return true
}

// Diverges reports whether a and b have diverged: neither dominates the other
// and they are not equal. This is the condition that triggers conflict
// resolution (§8.5).
func (a VersionVector) Diverges(b VersionVector) bool {
	return !a.Equal(b) && !a.Dominates(b) && !b.Dominates(a)
}

// Devices returns the set of device IDs with non-zero counters, sorted for
// deterministic iteration.
func (a VersionVector) Devices() []DeviceID {
	devs := make([]DeviceID, 0, len(a))
	for id, c := range a {
		if c > 0 {
			devs = append(devs, id)
		}
	}
	sort.Slice(devs, func(i, j int) bool { return devs[i] < devs[j] })
	return devs
}

// MarshalJSON serialises the vector as a sorted JSON object. The sorted order
// ensures deterministic output.
func (a VersionVector) MarshalJSON() ([]byte, error) {
	if a == nil {
		return []byte("{}"), nil
	}
	type entry struct {
		ID  string `json:"id"`
		Val uint64 `json:"val"`
	}
	entries := make([]entry, 0, len(a))
	for id, c := range a {
		if c > 0 {
			entries = append(entries, entry{ID: string(id), Val: c})
		}
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].ID < entries[j].ID })
	// Use a temporary map for compact JSON output.
	m := make(map[string]uint64, len(entries))
	for _, e := range entries {
		m[e.ID] = e.Val
	}
	return json.Marshal(m)
}

// UnmarshalJSON deserialises a version vector from JSON.
func (a *VersionVector) UnmarshalJSON(data []byte) error {
	var m map[string]uint64
	if err := json.Unmarshal(data, &m); err != nil {
		return err
	}
	if *a == nil {
		*a = make(VersionVector, len(m))
	}
	for k, v := range m {
		(*a)[DeviceID(k)] = v
	}
	return nil
}
