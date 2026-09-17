package audit

import (
	"bufio"
	"context"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// HIBPChecker tests whether a password has appeared in known data breaches
// using the Have I Been Pwned k-anonymity protocol.
type HIBPChecker interface {
	// Check reports whether the password has been seen in breaches.
	// It sends only the first 5 characters of the SHA-1 hash to the API
	// and compares the suffixes locally. The full hash never leaves the
	// machine.
	Check(ctx context.Context, password string) (bool, error)
}

// HIBPClient implements HIBPChecker against the live HIBP API.
type HIBPClient struct {
	// Endpoint is the HIBP API base URL. Defaults to
	// "https://api.pwnedpasswords.com/range/".
	Endpoint string
	// Client is the HTTP client used for requests.
	Client *http.Client
	// CacheDir persists fetched ranges between runs, so an audit does not
	// re-download what yesterday's audit already saw. Empty disables the
	// disk cache — it is an optimisation, never a dependency. Only the
	// 5-character hash prefixes are stored, which is exactly what the
	// k-anonymity protocol already sends to the API.
	CacheDir string
	// cache stores previously fetched ranges to avoid redundant API calls.
	// Key: 5-char SHA-1 prefix. Value: map of suffix → count.
	cache map[string]map[string]int
	// mu protects the cache.
	mu sync.Mutex
}

// hibpCacheTTL bounds how long a fetched range is trusted. HIBP adds new
// breaches continuously; a day-old answer is recent enough, a year-old one
// is not.
const hibpCacheTTL = 24 * time.Hour

// NewHIBPClient returns a client configured for the production HIBP API.
func NewHIBPClient() *HIBPClient {
	return &HIBPClient{
		Endpoint: "https://api.pwnedpasswords.com/range/",
		Client: &http.Client{
			Timeout: 10 * time.Second,
		},
		cache: make(map[string]map[string]int),
	}
}

// Check tests password against the HIBP database using k-anonymity.
func (c *HIBPClient) Check(ctx context.Context, password string) (bool, error) {
	hash := sha1Hash(password)
	prefix := sha1Prefix(hash)
	suffix := sha1Suffix(hash)

	// Check cache first.
	c.mu.Lock()
	suffixes, ok := c.cache[prefix]
	c.mu.Unlock()
	if !ok {
		// The disk cache from previous runs comes before the network: an
		// audit over an unchanged store is then entirely offline.
		var err error
		suffixes, ok, err = c.readCache(prefix)
		if err != nil {
			return false, err
		}
		if !ok {
			suffixes, err = c.fetchRange(ctx, prefix)
			if err != nil {
				return false, err
			}
			c.writeCache(prefix, suffixes)
		}
		c.mu.Lock()
		if c.cache == nil {
			c.cache = make(map[string]map[string]int)
		}
		c.cache[prefix] = suffixes
		c.mu.Unlock()
	}

	_, found := suffixes[suffix]
	return found, nil
}

// fetchRange queries the HIBP API for all hash suffixes matching the given
// 5-character prefix. The API returns lines of "SUFFIX:COUNT".
func (c *HIBPClient) fetchRange(ctx context.Context, prefix string) (map[string]int, error) {
	url := c.Endpoint + prefix
	if c.Endpoint == "" {
		url = "https://api.pwnedpasswords.com/range/" + prefix
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("hibp: %w", err)
	}
	// Add the adc parameter to disable padded responses, which are larger.
	req.Header.Set("User-Agent", "binpass-audit")

	resp, err := c.Client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("hibp: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("hibp: API returned %d", resp.StatusCode)
	}

	suffixes := make(map[string]int)
	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}
		// The API returns suffixes in uppercase.
		suffixes[parts[0]] = 0 // We don't need the count for our purposes.
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("hibp: reading response: %w", err)
	}

	return suffixes, nil
}

// noopHIBP is a no-op HIBP checker for when the check is disabled.
type noopHIBP struct{}

func (noopHIBP) Check(_ context.Context, _ string) (bool, error) { return false, nil }

// readCache loads a range from the disk cache. A missing or stale file is a
// miss; an unreadable or malformed one is a miss too, never an error the
// audit fails on — the cache is an optimisation.
func (c *HIBPClient) readCache(prefix string) (map[string]int, bool, error) {
	if c.CacheDir == "" {
		return nil, false, nil
	}
	path := filepath.Join(c.CacheDir, prefix)
	fi, err := os.Stat(path)
	if err != nil || time.Since(fi.ModTime()) > hibpCacheTTL {
		return nil, false, nil
	}
	data, err := os.ReadFile(path) //nolint:gosec // file name is a 5-char hex prefix we wrote ourselves.
	if err != nil {
		return nil, false, nil
	}
	suffixes := make(map[string]int)
	for _, line := range strings.Split(string(data), "\n") {
		if line = strings.TrimSpace(line); line != "" {
			suffixes[line] = 0
		}
	}
	return suffixes, true, nil
}

// writeCache stores a range on disk, best-effort: a read-only or missing
// cache directory degrades to no cache, not to a failed audit.
func (c *HIBPClient) writeCache(prefix string, suffixes map[string]int) {
	if c.CacheDir == "" {
		return
	}
	if err := os.MkdirAll(c.CacheDir, 0o700); err != nil {
		return
	}
	var b strings.Builder
	for suffix := range suffixes {
		b.WriteString(suffix)
		b.WriteByte('\n')
	}
	tmp, err := os.CreateTemp(c.CacheDir, ".range-*") // 0600 by default.
	if err != nil {
		return
	}
	name := tmp.Name()
	if _, err := tmp.WriteString(b.String()); err != nil {
		_ = tmp.Close()
		_ = os.Remove(name)
		return
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(name)
		return
	}
	_ = os.Rename(name, filepath.Join(c.CacheDir, prefix))
}
