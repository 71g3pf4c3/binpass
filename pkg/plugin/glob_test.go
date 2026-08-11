package plugin_test

import (
	"testing"

	"github.com/71g3pf4c3/binpass/pkg/plugin"
	"github.com/stretchr/testify/assert"
)

func TestMatchPath(t *testing.T) {
	tests := []struct {
		name    string
		pattern string
		path    string
		want    bool
	}{
		{"** matches everything", "**", "a/b/c", true},
		{"** matches a top-level entry", "**", "solo", true},
		{"subtree matches a child", "a/**", "a/b", true},
		{"subtree matches a grandchild", "a/**", "a/b/c/d", true},
		{"subtree matches its own root", "a/**", "a", true},
		{"subtree does not match a sibling", "a/**", "b/c", false},
		{"subtree does not match a prefix collision", "a/**", "ab/c", false},

		// The distinction that makes * safe to grant.
		{"single star matches a direct child", "a/*", "a/b", true},
		{"single star does not cross a slash", "a/*", "a/b/c", false},
		{"single star does not match the root", "a/*", "a", false},

		{"exact match", "a/b", "a/b", true},
		{"exact match rejects a child", "a/b", "a/b/c", false},
		{"exact match rejects a parent", "a/b", "a", false},

		{"suffix within a segment", "*.token", "api.token", true},
		{"suffix does not cross a slash", "*.token", "svc/api.token", false},
		{"prefix within a segment", "aws-*", "aws-prod", true},
		{"star in the middle", "a*z", "abcz", true},
		{"star in the middle rejects a mismatch", "a*z", "abcy", false},
		{"multiple stars", "*-*-key", "prod-eu-key", true},

		{"star inside a path", "svc/*/key", "svc/prod/key", true},
		{"star inside a path is one segment", "svc/*/key", "svc/a/b/key", false},
		{"double star inside a path", "svc/**/key", "svc/a/b/key", true},
		{"double star inside a path spans nothing", "svc/**/key", "svc/key", true},

		{"empty pattern matches nothing", "", "a", false},
		{"leading slash is ignored", "/a/b", "a/b", true},
		{"trailing slash is ignored", "a/b/", "a/b", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, plugin.MatchPath(tt.pattern, tt.path))
		})
	}
}

func TestMatchAny(t *testing.T) {
	patterns := []string{"work/**", "personal/bank"}

	assert.True(t, plugin.MatchAny(patterns, "work/aws"))
	assert.True(t, plugin.MatchAny(patterns, "personal/bank"))
	assert.False(t, plugin.MatchAny(patterns, "personal/email"))
	assert.False(t, plugin.MatchAny(nil, "anything"),
		"an empty capability list must grant nothing, not everything")
}

// TestMatchAnyEmptyDeniesByDefault pins the direction of the default. A
// capability list that is absent from a manifest must deny, because the
// manifest is what the user consented to: reading absence as "allow all"
// would grant the whole store to a plugin that asked for nothing.
func TestMatchAnyEmptyDeniesByDefault(t *testing.T) {
	assert.False(t, plugin.MatchAny([]string{}, "a"))
}
