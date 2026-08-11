package sync

import (
	"math/rand"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---- Unit tests ----

func TestVersionVectorEqual(t *testing.T) {
	tests := []struct {
		name string
		a    VersionVector
		b    VersionVector
		want bool
	}{
		{"nil equal nil", nil, nil, true},
		{"empty equal empty", VersionVector{}, VersionVector{}, true},
		{"nil equal empty", nil, VersionVector{}, true},
		{"same entries", VersionVector{"a": 1, "b": 2}, VersionVector{"a": 1, "b": 2}, true},
		{"different counter", VersionVector{"a": 1}, VersionVector{"a": 2}, false},
		{"extra device", VersionVector{"a": 1, "b": 2}, VersionVector{"a": 1}, false},
		{"zero vs absent", VersionVector{"a": 0, "b": 1}, VersionVector{"b": 1}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.a.Equal(tt.b))
			assert.Equal(t, tt.want, tt.b.Equal(tt.a))
		})
	}
}

func TestVersionVectorDominates(t *testing.T) {
	tests := []struct {
		name string
		a    VersionVector
		b    VersionVector
		want bool
	}{
		{"nil does not dominate nil", nil, nil, false},
		{"empty does not dominate empty", VersionVector{}, VersionVector{}, false},
		{"a:1 dominates nil", VersionVector{"a": 1}, VersionVector{}, true},
		{"a:2 dominates a:1", VersionVector{"a": 2}, VersionVector{"a": 1}, true},
		{"a:1 does not dominate a:2", VersionVector{"a": 1}, VersionVector{"a": 2}, false},
		{"a:1 b:2 dominates a:1", VersionVector{"a": 1, "b": 2}, VersionVector{"a": 1}, true},
		{"diverging vectors", VersionVector{"a": 2, "b": 1}, VersionVector{"a": 1, "b": 2}, false},
		{"a:1 b:1 does not dominate a:2", VersionVector{"a": 1, "b": 1}, VersionVector{"a": 2}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.a.Dominates(tt.b))
		})
	}
}

func TestVersionVectorMerge(t *testing.T) {
	tests := []struct {
		name string
		a    VersionVector
		b    VersionVector
		want VersionVector
	}{
		{"nil merge nil", nil, nil, VersionVector{}},
		{"a merge nil", VersionVector{"a": 1}, nil, VersionVector{"a": 1}},
		{"nil merge b", nil, VersionVector{"b": 2}, VersionVector{"b": 2}},
		{"pointwise max", VersionVector{"a": 1, "b": 3}, VersionVector{"a": 2, "c": 4}, VersionVector{"a": 2, "b": 3, "c": 4}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.a.Merge(tt.b)
			assert.True(t, got.Equal(tt.want), "got %v, want %v", got, tt.want)
		})
	}
}

func TestVersionVectorIncrement(t *testing.T) {
	v := VersionVector{"a": 1}
	got := v.Increment("b", 5)
	assert.Equal(t, uint64(1), v["a"], "original unchanged")
	assert.Equal(t, uint64(5), got["b"])
	assert.Equal(t, uint64(1), got["a"])

	got2 := got.Increment("b", 3)
	assert.Equal(t, uint64(8), got2["b"])
}

func TestVersionVectorDiverges(t *testing.T) {
	tests := []struct {
		name string
		a    VersionVector
		b    VersionVector
		want bool
	}{
		{"equal does not diverge", VersionVector{"a": 1}, VersionVector{"a": 1}, false},
		{"dominates does not diverge", VersionVector{"a": 2}, VersionVector{"a": 1}, false},
		{"diverging", VersionVector{"a": 2, "b": 1}, VersionVector{"a": 1, "b": 2}, true},
		{"both nil", nil, nil, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.a.Diverges(tt.b))
		})
	}
}

func TestVersionVectorCloneIsolation(t *testing.T) {
	original := VersionVector{"a": 1, "b": 2}
	clone := original.Clone()
	clone["a"] = 99
	clone["c"] = 10
	assert.Equal(t, uint64(1), original["a"], "original must not be mutated")
	_, ok := original["c"]
	assert.False(t, ok, "original must not gain keys from clone")
}

func TestVersionVectorJSONRoundTrip(t *testing.T) {
	v := VersionVector{"thinkpad": 3, "phone": 7}
	data, err := v.MarshalJSON()
	require.NoError(t, err)

	var got VersionVector
	require.NoError(t, got.UnmarshalJSON(data))
	assert.True(t, v.Equal(got))
}

func TestVersionVectorDevices(t *testing.T) {
	v := VersionVector{"c": 1, "a": 2, "b": 3, "z": 0}
	devs := v.Devices()
	assert.Equal(t, []DeviceID{"a", "b", "c"}, devs)
}

// ---- Property tests ----

func TestProperty_EqualIsReflexive(t *testing.T) {
	for i := 0; i < 1000; i++ {
		v := randomVV(t, rand.New(rand.NewSource(int64(i))))
		assert.True(t, v.Equal(v), "VV must equal itself: %v", v)
	}
}

func TestProperty_EqualIsSymmetric(t *testing.T) {
	for i := 0; i < 1000; i++ {
		rng := rand.New(rand.NewSource(int64(i)))
		a := randomVV(t, rng)
		b := randomVV(t, rng)
		assert.Equal(t, a.Equal(b), b.Equal(a))
	}
}

func TestProperty_DominatesIsAntisymmetric(t *testing.T) {
	for i := 0; i < 1000; i++ {
		rng := rand.New(rand.NewSource(int64(i)))
		a := randomVV(t, rng)
		b := randomVV(t, rng)
		if a.Dominates(b) && b.Dominates(a) {
			t.Fatalf("both dominate each other: a=%v b=%v", a, b)
		}
	}
}

func TestProperty_MergeIsCommutative(t *testing.T) {
	for i := 0; i < 1000; i++ {
		rng := rand.New(rand.NewSource(int64(i)))
		a := randomVV(t, rng)
		b := randomVV(t, rng)
		ab := a.Merge(b)
		ba := b.Merge(a)
		assert.True(t, ab.Equal(ba), "merge(a,b) must equal merge(b,a): a=%v b=%v", a, b)
	}
}

func TestProperty_MergeIsIdempotent(t *testing.T) {
	for i := 0; i < 1000; i++ {
		rng := rand.New(rand.NewSource(int64(i)))
		a := randomVV(t, rng)
		b := randomVV(t, rng)
		once := a.Merge(b)
		twice := once.Merge(b)
		assert.True(t, once.Equal(twice), "merge(merge(a,b),b) must equal merge(a,b)")
	}
}

func TestProperty_MergeSubsumesBoth(t *testing.T) {
	for i := 0; i < 1000; i++ {
		rng := rand.New(rand.NewSource(int64(i)))
		a := randomVV(t, rng)
		b := randomVV(t, rng)
		m := a.Merge(b)
		// The merge result must dominate or equal each input.
		if !m.Equal(a) {
			assert.True(t, m.Dominates(a), "merge(a,b) must dominate a: m=%v a=%v", m, a)
		}
		if !m.Equal(b) {
			assert.True(t, m.Dominates(b), "merge(a,b) must dominate b: m=%v b=%v", m, b)
		}
	}
}

func TestProperty_IncrementAndDominates(t *testing.T) {
	for i := 0; i < 1000; i++ {
		rng := rand.New(rand.NewSource(int64(i)))
		v := randomVV(t, rng)
		device := DeviceID("d")
		next := v.Increment(device, 1)
		assert.True(t, next.Dominates(v) || next.Equal(v), "increment must dominate or equal: next=%v v=%v", next, v)
		// If v already has a non-zero counter for device, increment must dominate.
		if v[device] > 0 {
			assert.True(t, next.Dominates(v), "increment of existing counter must dominate: next=%v v=%v", next, v)
		}
	}
}

func TestProperty_JSONRoundTrip(t *testing.T) {
	for i := 0; i < 1000; i++ {
		rng := rand.New(rand.NewSource(int64(i)))
		v := randomVV(t, rng)
		data, err := v.MarshalJSON()
		require.NoError(t, err)
		var got VersionVector
		require.NoError(t, got.UnmarshalJSON(data))
		assert.True(t, v.Equal(got), "round-trip must preserve VV: original=%v got=%v", v, got)
	}
}

// randomVV generates a random version vector for property testing.
func randomVV(t *testing.T, rng *rand.Rand) VersionVector {
	t.Helper()
	n := rng.Intn(5) + 1
	v := make(VersionVector, n)
	for i := 0; i < n; i++ {
		device := DeviceID(string(rune('a' + rng.Intn(6))))
		v[device] = uint64(rng.Intn(20))
	}
	return v
}
