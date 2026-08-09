package audit

import (
	"testing"
)

func TestPasswordStrength(t *testing.T) {
	tests := []struct {
		password string
		min      int // minimum expected score
	}{
		{"", 0},
		{"a", 0},
		{"password", 0},
		{"12345678", 0},
		{"correct-horse-battery-staple", 4},
		{"Tr0ub4dor&3", 2},
		{"Kk7N9!mP2xLq", 3},
	}

	for _, tc := range tests {
		t.Run(tc.password, func(t *testing.T) {
			score := passwordStrength(tc.password)
			if score < tc.min {
				t.Errorf("passwordStrength(%q) = %d, want >= %d", tc.password, score, tc.min)
			}
		})
	}
}

func TestSHA1Hash(t *testing.T) {
	// Known test vector: SHA-1("password") = 5BAA6...
	hash := sha1Hash("password")
	if len(hash) != 40 {
		t.Errorf("SHA-1 hash length = %d, want 40", len(hash))
	}
	if hash[:5] != "5BAA6" {
		t.Errorf("SHA-1(\"password\") prefix = %q, want %q", hash[:5], "5BAA6")
	}
}

func TestSHA1PrefixSuffix(t *testing.T) {
	hash := sha1Hash("test")
	prefix := sha1Prefix(hash)
	suffix := sha1Suffix(hash)
	if len(prefix) != 5 {
		t.Errorf("prefix length = %d, want 5", len(prefix))
	}
	if len(suffix) != 35 {
		t.Errorf("suffix length = %d, want 35", len(suffix))
	}
	if prefix+suffix != hash {
		t.Errorf("prefix + suffix != hash: %q + %q != %q", prefix, suffix, hash)
	}
}

func TestCheckExpiry(t *testing.T) {
	tests := []struct {
		name    string
		body    string
		expired bool
	}{
		{
			name:    "no expire field",
			body:    "hunter2\nusername: alice",
			expired: false,
		},
		{
			name:    "past date",
			body:    "hunter2\nexpires: 2020-01-01",
			expired: true,
		},
		{
			name:    "future date",
			body:    "hunter2\nexpires: 2099-01-01",
			expired: false,
		},
		{
			name:    "RFC3339 past",
			body:    "hunter2\nexpire: 2020-06-15T00:00:00Z",
			expired: true,
		},
		{
			name:    "European date format past",
			body:    "hunter2\nexpiry: 01.01.2020",
			expired: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			sec := parseTestSecret(tc.body)
			expired, when := checkExpiry(sec, testNow)
			if expired != tc.expired {
				t.Errorf("checkExpiry() expired = %v, want %v (when = %v)", expired, tc.expired, when)
			}
		})
	}
}
