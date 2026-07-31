package manifest

// Ordering describes the causal relationship between two version vectors.
type Ordering int

// Version-vector orderings.
const (
	// Equal means the vectors are identical.
	Equal Ordering = iota
	// Dominates means the left vector is strictly newer (descends from right).
	Dominates
	// DominatedBy means the left vector is strictly older.
	DominatedBy
	// Concurrent means neither descends from the other (a conflict).
	Concurrent
)

// Compare returns the causal ordering of a relative to b.
func Compare(a, b VersionVector) Ordering {
	aGreater, bGreater := false, false

	keys := make(map[string]struct{}, len(a)+len(b))
	for k := range a {
		keys[k] = struct{}{}
	}
	for k := range b {
		keys[k] = struct{}{}
	}
	for k := range keys {
		av, bv := a[k], b[k]
		if av > bv {
			aGreater = true
		} else if av < bv {
			bGreater = true
		}
	}

	switch {
	case aGreater && bGreater:
		return Concurrent
	case aGreater:
		return Dominates
	case bGreater:
		return DominatedBy
	default:
		return Equal
	}
}

// MergeVV returns the pointwise maximum of a and b.
func MergeVV(a, b VersionVector) VersionVector {
	out := make(VersionVector, len(a)+len(b))
	for k, v := range a {
		out[k] = v
	}
	for k, v := range b {
		if v > out[k] {
			out[k] = v
		}
	}
	return out
}

// Bump increments the counter for device in a copy of the vector.
func Bump(vv VersionVector, device string) VersionVector {
	out := make(VersionVector, len(vv)+1)
	for k, v := range vv {
		out[k] = v
	}
	out[device]++
	return out
}
