package manifest

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCompare(t *testing.T) {
	cases := []struct {
		name string
		a, b VersionVector
		want Ordering
	}{
		{"equal", VersionVector{"d": 1}, VersionVector{"d": 1}, Equal},
		{"dominates", VersionVector{"d": 2}, VersionVector{"d": 1}, Dominates},
		{"dominated", VersionVector{"d": 1}, VersionVector{"d": 2}, DominatedBy},
		{"concurrent", VersionVector{"a": 1}, VersionVector{"b": 1}, Concurrent},
		{"empty-equal", VersionVector{}, VersionVector{}, Equal},
		{"disjoint-dominates", VersionVector{"a": 1, "b": 1}, VersionVector{"a": 1}, Dominates},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			assert.Equal(t, c.want, Compare(c.a, c.b))
		})
	}
}

func TestMergeVV(t *testing.T) {
	got := MergeVV(VersionVector{"a": 1, "b": 3}, VersionVector{"a": 2, "c": 1})
	assert.Equal(t, VersionVector{"a": 2, "b": 3, "c": 1}, got)
}

func TestBump(t *testing.T) {
	got := Bump(VersionVector{"a": 1}, "a")
	assert.Equal(t, uint64(2), got["a"])
	got2 := Bump(nil, "new")
	assert.Equal(t, uint64(1), got2["new"])
}

// FuzzCompareSymmetry checks that Compare is consistent under argument swap.
func FuzzCompareSymmetry(f *testing.F) {
	f.Add(uint64(1), uint64(2), uint64(0), uint64(0))
	f.Fuzz(func(t *testing.T, a1, a2, b1, b2 uint64) {
		a := VersionVector{"x": a1, "y": a2}
		b := VersionVector{"x": b1, "y": b2}
		fwd := Compare(a, b)
		rev := Compare(b, a)
		switch fwd {
		case Equal:
			assert.Equal(t, Equal, rev)
		case Dominates:
			assert.Equal(t, DominatedBy, rev)
		case DominatedBy:
			assert.Equal(t, Dominates, rev)
		case Concurrent:
			assert.Equal(t, Concurrent, rev)
		}
	})
}
