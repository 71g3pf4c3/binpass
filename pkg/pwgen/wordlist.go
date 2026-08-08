package pwgen

import (
	_ "embed"
	"strings"
	"sync"
)

// effLargeData is the EFF long wordlist, 7776 words chosen to be easy to type
// and hard to confuse. It is embedded so that diceware works with no data
// files to install.
//
//go:embed wordlists/eff_large.txt
var effLargeData string

// effLargeOnce guards the one-time split of the embedded list.
var effLargeOnce sync.Once

// effLarge holds the parsed wordlist.
var effLarge []string

// EFFLarge returns the EFF long wordlist. Each word contributes log2(7776) ≈
// 12.9 bits, so six words are about 77 bits of entropy.
func EFFLarge() []string {
	effLargeOnce.Do(func() {
		for _, line := range strings.Split(effLargeData, "\n") {
			if w := strings.TrimSpace(line); w != "" {
				effLarge = append(effLarge, w)
			}
		}
	})
	return effLarge
}
