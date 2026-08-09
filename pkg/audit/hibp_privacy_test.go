package audit

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestOnlyThePrefixLeavesTheMachine is the privacy claim the help text makes,
// checked rather than trusted: a breach lookup must never put the password,
// or enough of its hash to identify it, on the wire.
func TestOnlyThePrefixLeavesTheMachine(t *testing.T) {
	const password = "correct horse battery staple"

	var seen []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = append(seen, r.URL.String()+"?"+r.URL.RawQuery+" "+r.Header.Get("User-Agent"))
		_, _ = w.Write([]byte("0000000000000000000000000000000000000:1\n"))
	}))
	defer srv.Close()

	c := &HIBPClient{Endpoint: srv.URL + "/range/", Client: srv.Client()}
	c.cache = map[string]map[string]int{}
	_, err := c.Check(context.Background(), password)
	require.NoError(t, err)
	require.Len(t, seen, 1)

	full := strings.ToUpper(sha1Hash(password))
	sent := seen[0]

	assert.NotContains(t, sent, password, "the password must never be sent")
	assert.NotContains(t, strings.ToUpper(sent), full, "the full hash must never be sent")
	assert.NotContains(t, strings.ToUpper(sent), sha1Suffix(sha1Hash(password)),
		"the suffix identifies the password and must stay local")
	assert.Contains(t, strings.ToUpper(sent), full[:5], "only the 5-character prefix is sent")
}
