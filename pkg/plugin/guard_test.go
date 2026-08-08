package plugin_test

import (
	"testing"

	"github.com/71g3pf4c3/binpass/pkg/plugin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// scoped returns a guard for a plugin restricted to the work subtree.
func scoped() *plugin.Guard {
	return plugin.NewGuard("demo", plugin.Capabilities{
		ReadPaths:  []string{"work/**"},
		WritePaths: []string{"work/scratch/**"},
		Decrypt:    true,
		Network:    []string{"api.example.com"},
		Exec:       []string{"curl"},
	}, true)
}

// TestUnrestrictedAllowsEverything covers the ordinary case: a binpass the
// user ran themselves must not be constrained by machinery meant for plugins.
func TestUnrestrictedAllowsEverything(t *testing.T) {
	g := plugin.Unrestricted()

	assert.True(t, g.CanRead("anything"))
	assert.True(t, g.CanWrite("anything"))
	assert.True(t, g.CanDecrypt("anything"))
	assert.NoError(t, g.CheckExec("rm"))
	assert.NoError(t, g.CheckNetwork("evil.example"))
}

func TestGuardScopesAccess(t *testing.T) {
	g := scoped()

	assert.True(t, g.CanRead("work/aws"))
	assert.False(t, g.CanRead("personal/bank"))

	assert.True(t, g.CanWrite("work/scratch/tmp"))
	assert.False(t, g.CanWrite("work/aws"), "read access is not write access")

	assert.NoError(t, g.CheckExec("curl"))
	assert.Error(t, g.CheckExec("rm"))

	assert.NoError(t, g.CheckNetwork("api.example.com"))
	assert.Error(t, g.CheckNetwork("evil.example"))
}

// TestDecryptIsSeparateFromRead is the distinction that lets a plugin take an
// inventory of the store without ever being shown a password.
func TestDecryptIsSeparateFromRead(t *testing.T) {
	g := plugin.NewGuard("lister", plugin.Capabilities{
		ReadPaths: []string{"**"},
		Decrypt:   false,
	}, true)

	assert.True(t, g.CanRead("work/aws"), "it may know the entry exists")
	assert.False(t, g.CanDecrypt("work/aws"), "but not what it contains")

	err := g.CheckDecrypt("work/aws")
	require.Error(t, err)
	assert.ErrorIs(t, err, plugin.ErrDenied)
	assert.ErrorContains(t, err, "did not request decrypt")
}

// TestEmptyCapabilitiesDenyEverything pins the default. A manifest that
// requests nothing must receive nothing, or the consent the user gave would
// not mean what it says.
func TestEmptyCapabilitiesDenyEverything(t *testing.T) {
	g := plugin.NewGuard("silent", plugin.Capabilities{}, true)

	assert.False(t, g.CanRead("a"))
	assert.False(t, g.CanWrite("a"))
	assert.False(t, g.CanDecrypt("a"))
	assert.Error(t, g.CheckExec("echo"))
	assert.Error(t, g.CheckNetwork("example.com"))
}

// TestFilterReadableHidesTheRest checks that listing is filtered rather than
// refused, so a scoped plugin sees a coherent store instead of an error it
// would have to work around.
func TestFilterReadableHidesTheRest(t *testing.T) {
	g := scoped()

	got := g.FilterReadable([]string{"work/aws", "personal/bank", "work/gcp"})
	assert.Equal(t, []string{"work/aws", "work/gcp"}, got)
}

func TestFilterReadableIsATransparentPassThroughWhenUnrestricted(t *testing.T) {
	names := []string{"a", "b"}
	assert.Equal(t, names, plugin.Unrestricted().FilterReadable(names))
}

// TestDenialNamesTheFix reflects that a plugin author's first question is
// always which pattern they need to add.
func TestDenialNamesTheFix(t *testing.T) {
	err := scoped().CheckWrite("personal/bank")
	require.Error(t, err)

	assert.ErrorContains(t, err, "personal/bank", "the refused entry")
	assert.ErrorContains(t, err, "work/scratch/**", "what was allowed instead")
	assert.ErrorContains(t, err, "demo", "which plugin was refused")
}

func TestActiveCapabilities(t *testing.T) {
	tests := []struct {
		name           string
		env            map[string]string
		wantRestricted bool
		wantRead       []string
	}{
		{
			name:           "a binpass the user ran themselves",
			env:            map[string]string{},
			wantRestricted: false,
		},
		{
			// An unmanaged plugin could read the store directly without
			// asking binpass, so restricting the callback would block
			// nothing while breaking every simple plugin.
			name:           "an unmanaged plugin carries no grant",
			env:            map[string]string{plugin.EnvPluginName: "demo"},
			wantRestricted: false,
		},
		{
			name: "a managed plugin carries its grant",
			env: map[string]string{
				plugin.EnvPluginName:   "demo",
				plugin.EnvCapabilities: `{"read_paths":["work/**"]}`,
			},
			wantRestricted: true,
			wantRead:       []string{"work/**"},
		},
		{
			// Being told a plugin is running but not what it may do is not
			// a reason to allow everything.
			name: "an unreadable grant denies rather than allows",
			env: map[string]string{
				plugin.EnvPluginName:   "demo",
				plugin.EnvCapabilities: "{{{garbage",
			},
			wantRestricted: true,
			wantRead:       nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			caps, _, restricted := plugin.ActiveCapabilities(func(k string) string {
				return tt.env[k]
			})
			assert.Equal(t, tt.wantRestricted, restricted)
			assert.Equal(t, tt.wantRead, caps.ReadPaths)
		})
	}
}
