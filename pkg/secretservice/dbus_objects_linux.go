//go:build linux

package secretservice

import (
	"github.com/godbus/dbus/v5"
)

// collection is the D-Bus object for one collection.
type collection struct {
	// service is the provider that owns it.
	service *Service
	// name is the collection name, which is also its directory.
	name string
}

// CreateItem implements org.freedesktop.Secret.Collection.CreateItem.
func (c *collection) CreateItem(properties map[string]dbus.Variant, secretValue Secret, replace bool) (dbus.ObjectPath, dbus.ObjectPath, *dbus.Error) {
	sess, ok := c.service.session(secretValue.Session)
	if !ok {
		return "/", "/", dbusErrf("org.freedesktop.Secret.Error.NoSession", "no such session")
	}

	plaintext, err := sess.Decrypt(secretValue.Value, secretValue.Parameters)
	if err != nil {
		return "/", "/", dbusErrf("org.freedesktop.DBus.Error.InvalidArgs", "%s", err)
	}

	it := &Item{
		Label:      stringProp(properties, "org.freedesktop.Secret.Item.Label"),
		Attributes: attributesProp(properties, "org.freedesktop.Secret.Item.Attributes"),
		Secret:     string(plaintext),
	}

	stored, err := c.service.store.CreateItem(c.name, it, replace)
	if err != nil {
		return "/", "/", dbusErrf("org.freedesktop.Secret.Error.NoSuchObject", "%s", err)
	}
	if err := c.service.exportItem(c.name, stored); err != nil {
		return "/", "/", dbusErrf("org.freedesktop.Secret.Error.NoSuchObject", "%s", err)
	}

	return itemObjectPath(c.name, stored.ID), dbus.ObjectPath("/"), nil
}

// SearchItems implements org.freedesktop.Secret.Collection.SearchItems.
func (c *collection) SearchItems(attributes map[string]string) ([]dbus.ObjectPath, *dbus.Error) {
	items, err := c.service.store.Search(c.name, attributes)
	if err != nil {
		return nil, dbusErrf("org.freedesktop.Secret.Error.NoSuchObject", "%s", err)
	}
	out := make([]dbus.ObjectPath, 0, len(items))
	for _, it := range items {
		out = append(out, itemObjectPath(c.name, it.ID))
	}
	return out, nil
}

// Delete implements org.freedesktop.Secret.Collection.Delete.
func (c *collection) Delete() (dbus.ObjectPath, *dbus.Error) {
	return dbus.ObjectPath("/"), dbusErrf("org.freedesktop.Secret.Error.NotSupported",
		"deleting a whole collection would remove entries from the password store; "+
			"delete the items, or remove the directory with binpass rm")
}

// itemObject is the D-Bus object for one item.
type itemObject struct {
	// service is the provider that owns it.
	service *Service
	// collection is the collection holding the item.
	collection string
	// id is the item identifier.
	id string
}

// GetSecret implements org.freedesktop.Secret.Item.GetSecret.
//
// This is where a password actually leaves the store, so it is where the
// policy is enforced: the caller is identified from the bus message, and a
// denial returns an error without anything being decrypted for the wire.
func (i *itemObject) GetSecret(message dbus.Message, session dbus.ObjectPath) (Secret, *dbus.Error) {
	sess, ok := i.service.session(session)
	if !ok {
		return Secret{}, dbusErrf("org.freedesktop.Secret.Error.NoSession", "no such session")
	}

	it, err := i.service.store.Item(i.collection, i.id)
	if err != nil {
		return Secret{}, dbusErrf("org.freedesktop.Secret.Error.NoSuchObject", "%s", err)
	}

	sender := senderOf(message)
	allowed, reason := i.service.policy.Allow(sender, i.collection, it)
	i.service.policy.Record(sender, i.collection, it, allowed)
	if !allowed {
		return Secret{}, dbusErrf("org.freedesktop.Secret.Error.IsLocked", "%s", reason)
	}

	out, err := encodeSecret(sess, session, it.Secret)
	if err != nil {
		return Secret{}, dbusErrf("org.freedesktop.Secret.Error.NoSession", "%s", err)
	}
	return out, nil
}

// SetSecret implements org.freedesktop.Secret.Item.SetSecret.
func (i *itemObject) SetSecret(secretValue Secret) *dbus.Error {
	sess, ok := i.service.session(secretValue.Session)
	if !ok {
		return dbusErrf("org.freedesktop.Secret.Error.NoSession", "no such session")
	}
	plaintext, err := sess.Decrypt(secretValue.Value, secretValue.Parameters)
	if err != nil {
		return dbusErrf("org.freedesktop.DBus.Error.InvalidArgs", "%s", err)
	}

	it, err := i.service.store.Item(i.collection, i.id)
	if err != nil {
		return dbusErrf("org.freedesktop.Secret.Error.NoSuchObject", "%s", err)
	}
	it.Secret = string(plaintext)

	if _, err := i.service.store.CreateItem(i.collection, it, true); err != nil {
		return dbusErrf("org.freedesktop.Secret.Error.NoSuchObject", "%s", err)
	}
	return nil
}

// Delete implements org.freedesktop.Secret.Item.Delete.
func (i *itemObject) Delete() (dbus.ObjectPath, *dbus.Error) {
	if err := i.service.store.DeleteItem(i.collection, i.id); err != nil {
		return "/", dbusErrf("org.freedesktop.Secret.Error.NoSuchObject", "%s", err)
	}
	p := itemObjectPath(i.collection, i.id)
	_ = i.service.conn.Export(nil, p, ItemInterface)
	return dbus.ObjectPath("/"), nil
}

// sessionObject is the D-Bus object for one transport session.
type sessionObject struct {
	// service is the provider that owns it.
	service *Service
	// path is this session's object path.
	path dbus.ObjectPath
}

// Close implements org.freedesktop.Secret.Session.Close.
func (s *sessionObject) Close() *dbus.Error {
	s.service.closeSession(s.path)
	return nil
}

// stringProp reads a string property from a client-supplied map.
func stringProp(props map[string]dbus.Variant, key string) string {
	v, ok := props[key]
	if !ok {
		return ""
	}
	s, _ := v.Value().(string)
	return s
}

// attributesProp reads the attributes property.
func attributesProp(props map[string]dbus.Variant, key string) map[string]string {
	v, ok := props[key]
	if !ok {
		return map[string]string{}
	}
	m, ok := v.Value().(map[string]string)
	if !ok {
		return map[string]string{}
	}
	return m
}

// senderOf returns the unique bus name of whoever sent a message.
func senderOf(message dbus.Message) string {
	if v, ok := message.Headers[dbus.FieldSender]; ok {
		s, _ := v.Value().(string)
		return s
	}
	return ""
}
