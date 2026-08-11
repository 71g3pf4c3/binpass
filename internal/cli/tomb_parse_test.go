package cli

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseSize(t *testing.T) {
	tests := []struct {
		in      string
		want    int64
		wantErr bool
	}{
		{"", 0, false},
		{"1024", 1024, false},
		// The suffix forms are the reason this function exists: a tomb sized
		// at "1G" must not come out as one byte.
		{"1K", 1 << 10, false},
		{"512M", 512 << 20, false},
		{"1G", 1 << 30, false},
		{"2g", 2 << 30, false},
		{"nonsense", 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			got, err := parseSize(tt.in)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestParseDuration(t *testing.T) {
	d, err := parseDuration("")
	require.NoError(t, err)
	assert.Zero(t, d, "no timer means no auto-close, not an error")

	d, err = parseDuration("15m")
	require.NoError(t, err)
	assert.Equal(t, 15*time.Minute, d)

	_, err = parseDuration("soon")
	assert.Error(t, err)
}
