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
//
// Storing is as much a decision as reading: a program the policy refuses
// must not be able to replace a password its owner then retypes somewhere
// else, nor to fill a collection with items of its own. The check happens
// before the client's secret is decrypted, so a refusal costs nothing.
func (c *collection) CreateItem(message dbus.Message, properties map[string]dbus.Variant, secretValue Secret, replace bool) (dbus.ObjectPath, dbus.ObjectPath, *dbus.Error) {
	sender := senderOf(message)
	sess, ok := c.service.session(secretValue.Session, sender)
	if !ok {
		return "/", "/", dbusErrf("org.freedesktop.Secret.Error.NoSession", "no such session")
	}

	it := &Item{
		Label:      stringProp(properties, "org.freedesktop.Secret.Item.Label"),
		Attributes: attributesProp(properties, "org.freedesktop.Secret.Item.Attributes"),
	}

	allowed, reason := c.service.policy.Allow(sender, c.name, it)
	c.service.policy.Record(sender, c.name, it, allowed)
	if !allowed {
		return "/", "/", dbusErrf("org.freedesktop.Secret.Error.IsLocked", "%s", reason)
	}

	plaintext, err := sess.Decrypt(secretValue.Value, secretValue.Parameters)
	if err != nil {
		return "/", "/", dbusErrf("org.freedesktop.DBus.Error.InvalidArgs", "%s", err)
	}
	it.Secret = string(plaintext)

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
//
// Same filtering as the service-level search: a caller a deny rule covers
// must not learn which items exist. Nothing is decrypted here, so no audit
// record is written.
func (c *collection) SearchItems(message dbus.Message, attributes map[string]string) ([]dbus.ObjectPath, *dbus.Error) {
	sender := senderOf(message)
	items, err := c.service.store.Search(c.name, attributes)
	if err != nil {
		return nil, dbusErrf("org.freedesktop.Secret.Error.NoSuchObject", "%s", err)
	}
	out := make([]dbus.ObjectPath, 0, len(items))
	for _, it := range items {
		if allowed, _ := c.service.policy.Allow(sender, c.name, it); !allowed {
			continue
		}
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
	sender := senderOf(message)
	sess, ok := i.service.session(session, sender)
	if !ok {
		return Secret{}, dbusErrf("org.freedesktop.Secret.Error.NoSession", "no such session")
	}

	it, err := i.service.store.Item(i.collection, i.id)
	if err != nil {
		return Secret{}, dbusErrf("org.freedesktop.Secret.Error.NoSuchObject", "%s", err)
	}

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
//
// Overwriting an item is checked against the policy for the same reason
// CreateItem is: a denial that only covered reads would leave a refused
// program free to swap the stored password for one of its own.
func (i *itemObject) SetSecret(message dbus.Message, secretValue Secret) *dbus.Error {
	sender := senderOf(message)
	sess, ok := i.service.session(secretValue.Session, sender)
	if !ok {
		return dbusErrf("org.freedesktop.Secret.Error.NoSession", "no such session")
	}

	it, err := i.service.store.Item(i.collection, i.id)
	if err != nil {
		return dbusErrf("org.freedesktop.Secret.Error.NoSuchObject", "%s", err)
	}

	allowed, reason := i.service.policy.Allow(sender, i.collection, it)
	i.service.policy.Record(sender, i.collection, it, allowed)
	if !allowed {
		return dbusErrf("org.freedesktop.Secret.Error.IsLocked", "%s", reason)
	}

	plaintext, err := sess.Decrypt(secretValue.Value, secretValue.Parameters)
	if err != nil {
		return dbusErrf("org.freedesktop.DBus.Error.InvalidArgs", "%s", err)
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
//
// Only the client that opened the session may close it. Session paths are
// sequential small integers, so without this any process on the bus could
// enumerate them and drop another program's session, which fails that
// program's next read.
func (s *sessionObject) Close(message dbus.Message) *dbus.Error {
	if !s.service.closeSession(s.path, senderOf(message)) {
		return dbusErrf("org.freedesktop.Secret.Error.NoSession", "no such session")
	}
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
