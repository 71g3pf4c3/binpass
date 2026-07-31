package cli

import "regexp"

// clipShorthand matches a `-c<N>` or `-q<N>` attached-number shorthand, which
// pass accepts but cobra does not; NormalizeArgs rewrites it to `-c=<N>`.
var clipShorthand = regexp.MustCompile(`^-([cq])([0-9]+)$`)

// NormalizeArgs rewrites pass-style attached shorthand flags (e.g. "-c2") into
// the cobra-friendly "-c=2" form so that "binpass show -c2 name" works exactly
// like "pass show -c2 name".
func NormalizeArgs(args []string) []string {
	out := make([]string, 0, len(args))
	for _, a := range args {
		if m := clipShorthand.FindStringSubmatch(a); m != nil {
			out = append(out, "-"+m[1]+"="+m[2])
			continue
		}
		out = append(out, a)
	}
	return out
}
