//go:build linux

package secretservice

import (
	"testing"

	"github.com/godbus/dbus/v5"
	"github.com/stretchr/testify/assert"
)

func TestItemPathsRoundTrip(t *testing.T) {
	p := itemObjectPath("login", "4f3c9a2b")
	assert.Equal(t, dbus.ObjectPath("/org/freedesktop/secrets/collection/login/4f3c9a2b"), p)

	collection, id, ok := parseItemPath(p)
	assert.True(t, ok)
	assert.Equal(t, "login", collection)
	assert.Equal(t, "4f3c9a2b", id)
}

func TestParseItemPathRejectsAnythingElse(t *testing.T) {
	for name, p := range map[string]dbus.ObjectPath{
		"a collection, not an item": "/org/freedesktop/secrets/collection/login",
		"the service itself":        "/org/freedesktop/secrets",
		"a session":                 "/org/freedesktop/secrets/session/s1",
		"someone else's object":     "/org/gnome/keyring/item/1",
		"empty id":                  "/org/freedesktop/secrets/collection/login/",
		"empty collection":          "/org/freedesktop/secrets/collection//4f3c",
	} {
		t.Run(name, func(t *testing.T) {
			_, _, ok := parseItemPath(p)
			assert.False(t, ok)
		})
	}
}

// TestSanitiseCollectionName covers a label supplied by another program. It
// becomes both a directory name and a D-Bus path element, so a label with a
// slash in it would be a path traversal and one with a space would produce
// an object path no client can address.
func TestSanitiseCollectionName(t *testing.T) {
	for input, want := range map[string]string{
		"login":          "login",
		"Login_1":        "Login_1",
		"my keyring":     "my_keyring",
		"../../etc":      "etc",
		"a/b":            "a_b",
		"unicode-пароль": "unicode",
		"":               DefaultCollection,
		"///":            DefaultCollection,
		"...":            DefaultCollection,
	} {
		t.Run(input, func(t *testing.T) {
			got := sanitiseCollectionName(input)
			assert.Equal(t, want, got)
			// Whatever comes out has to be usable as a path element, or the
			// collection cannot be exported at all.
			assert.NotContains(t, got, "/")
			assert.NotEmpty(t, got)
		})
	}
}

func TestSanitisedNamesMakeValidObjectPaths(t *testing.T) {
	for _, label := range []string{"my keyring", "../../etc", "a/b/c", "Ünïcödé"} {
		p := collectionPath(sanitiseCollectionName(label))
		assert.True(t, p.IsValid(), "%q produced the invalid object path %q", label, p)
	}
}

func TestStringAndAttributeProps(t *testing.T) {
	props := map[string]dbus.Variant{
		"org.freedesktop.Secret.Item.Label":      dbus.MakeVariant("GitHub"),
		"org.freedesktop.Secret.Item.Attributes": dbus.MakeVariant(map[string]string{"server": "github.com"}),
		"wrong.type":                             dbus.MakeVariant(42),
	}

	assert.Equal(t, "GitHub", stringProp(props, "org.freedesktop.Secret.Item.Label"))
	assert.Equal(t, "github.com", attributesProp(props, "org.freedesktop.Secret.Item.Attributes")["server"])

	// A client sending the wrong type, or nothing at all, must not panic the
	// provider: these come off the wire from another program.
	assert.Empty(t, stringProp(props, "missing"))
	assert.Empty(t, stringProp(props, "wrong.type"))
	assert.Empty(t, attributesProp(props, "missing"))
	assert.Empty(t, attributesProp(props, "wrong.type"))
}
