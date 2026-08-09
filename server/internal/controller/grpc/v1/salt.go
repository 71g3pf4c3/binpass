package v1

import "encoding/base64"

// encodeSalt renders a user salt as standard base64 for the wire.
func encodeSalt(salt []byte) string {
	return base64.StdEncoding.EncodeToString(salt)
}
