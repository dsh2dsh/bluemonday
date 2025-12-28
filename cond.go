package bluemonday

import "strings"

// PolicyCond is a condition, which defines should configured policy be applied
// or skipped. Some policies use it to do something conditionally, like
// [Policy.SetAttrIf].
type PolicyCond func(t *Token) bool

// DomainIn checks that current HTML element has parseable URL and its hostname
// or domain is one of given domains.
//
// This condition expects [Policy.RequireParseableURLs] set to true or it always
// evaluates to false.
func DomainIn(domains ...string) PolicyCond {
	return func(t *Token) bool {
		u := t.url()
		if u == nil {
			return false
		}

		hostname := u.Hostname()
		for _, s := range domains {
			if s == hostname {
				return true
			}

			before, ok := strings.CutSuffix(hostname, s)
			if ok && strings.HasSuffix(before, ".") {
				return true
			}
		}
		return false
	}
}
