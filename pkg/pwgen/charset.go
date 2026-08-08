package pwgen

import (
	"regexp"
	"strings"
)

// posixClasses maps the POSIX character classes pass accepts in
// PASSWORD_STORE_CHARACTER_SET to their expansions.
var posixClasses = map[string]string{
	"alnum":  "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
	"alpha":  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
	"digit":  "0123456789",
	"lower":  "abcdefghijklmnopqrstuvwxyz",
	"upper":  "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
	"punct":  "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~",
	"xdigit": "0123456789ABCDEFabcdef",
	"graph":  CharacterSet,
	"print":  CharacterSet + " ",
}

// classPattern matches a POSIX class reference such as "[:alnum:]".
var classPattern = regexp.MustCompile(`\[:([a-z]+):\]`)

// ExpandCharacterSet turns a pass-style character set specification into a
// literal alphabet. pass passes its value to tr(1), so specifications like
// "[:punct:][:alnum:]" must be understood rather than taken literally.
func ExpandCharacterSet(spec string) string {
	if spec == "" {
		return ""
	}
	var sb strings.Builder
	rest := spec
	for {
		loc := classPattern.FindStringSubmatchIndex(rest)
		if loc == nil {
			sb.WriteString(rest)
			break
		}
		sb.WriteString(rest[:loc[0]])
		if expansion, ok := posixClasses[rest[loc[2]:loc[3]]]; ok {
			sb.WriteString(expansion)
		}
		rest = rest[loc[1]:]
	}
	return dedupe(sb.String())
}

// dedupe removes repeated runes so that a character listed twice is not twice
// as likely to be chosen.
func dedupe(s string) string {
	seen := make(map[rune]bool, len(s))
	var sb strings.Builder
	for _, r := range s {
		if !seen[r] {
			seen[r] = true
			sb.WriteRune(r)
		}
	}
	return sb.String()
}
