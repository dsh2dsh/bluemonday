package css

import (
	"regexp"
	"strconv"
	"strings"

	"github.com/aymerick/douceur/parser"
)

var cssUnicodeChar = regexp.MustCompile(`\\[0-9a-f]{1,6} ?`)

// Policy encapsulates the allowlist of css styles that will be applied to the
// sanitised style attributes.
//
// You should use NewPolicy() to create a blank policy as the unexported fields
// contain maps that need to be initialized.
type Policy struct {
	elsAndStyles         map[string]map[string][]stylePolicy
	elsMatchingAndStyles map[*regexp.Regexp]map[string][]stylePolicy
	globalStyles         map[string][]stylePolicy
}

type stylePolicy struct {
	// handler to validate
	handler func(string) bool

	// optional pattern to match, when not nil the regexp needs to match otherwise
	// the property is removed
	regexp *regexp.Regexp

	// optional list of allowed property values, for properties which have a
	// defined list of allowed values; property will be removed if the value is
	// not allowed
	enum []string
}

// NewPolicy returns a blank policy with nothing allowed or permitted. This is
// the recommended way to start building a policy and you should now use
// AllowStyles() to construct the allowlist of HTML elements and attributes.
func NewPolicy() *Policy {
	p := &Policy{
		elsAndStyles:         make(map[string]map[string][]stylePolicy),
		elsMatchingAndStyles: make(map[*regexp.Regexp]map[string][]stylePolicy),
		globalStyles:         make(map[string][]stylePolicy),
	}
	return p
}

// AllowStyles takes a range of CSS property names and returns a style policy
// builder that allows you to specify the pattern and scope of the allowed
// property.
//
// The style policy is only added to the core policy when either Globally() or
// OnElements(...) are called.
func (self *Policy) AllowStyles(propertyNames ...string) *PolicyBuilder {
	return NewPolicyBuilder(self, propertyNames...)
}

// HasPolicies returns true if this Policy has any policy for given elementName.
func (self *Policy) HasPolicies(elementName string) bool {
	if len(self.globalStyles) > 0 {
		return true
	}

	if policies, ok := self.elsAndStyles[elementName]; ok && len(policies) > 0 {
		return true
	}

	// no specific element policy found, look for a pattern match
	for k, v := range self.elsMatchingAndStyles {
		if k.MatchString(elementName) && len(v) > 0 {
			return true
		}
	}
	return false
}

func (self *Policy) Sanitize(elementName, style string) string {
	if !self.HasPolicies(elementName) {
		return ""
	}

	sps := self.elsAndStyles[elementName]
	if len(sps) == 0 {
		sps = map[string][]stylePolicy{}
		// check for any matching elements, if we don't already have a policy found
		// if multiple matches are found they will be overwritten, it's best to not
		// have overlapping matchers
		for regex, policies := range self.elsMatchingAndStyles {
			if regex.MatchString(elementName) {
				for k, v := range policies {
					sps[k] = append(sps[k], v...)
				}
			}
		}
	}

	// Add semi-colon to end to fix parsing issue
	style = strings.TrimRight(style, " ")
	if len(style) > 0 && style[len(style)-1] != ';' {
		style += ";"
	}

	decs, err := parser.ParseDeclarations(style)
	if err != nil {
		return ""
	}

	var clean []string
	prefixes := [...]string{
		"-webkit-", "-moz-", "-ms-", "-o-", "mso-", "-xv-", "-atsc-", "-wap-",
		"-khtml-", "prince-", "-ah-", "-hp-", "-ro-", "-rim-", "-tc-",
	}

	for _, dec := range decs {
		tempProperty := strings.ToLower(dec.Property)
		tempValue := removeUnicode(strings.ToLower(dec.Value))
		for _, i := range prefixes {
			tempProperty = strings.TrimPrefix(tempProperty, i)
		}

		if spl, ok := sps[tempProperty]; ok {
			for _, sp := range spl {
				switch {
				case sp.handler != nil:
					if sp.handler(tempValue) {
						clean = append(clean, dec.Property+": "+dec.Value)
						continue
					}
				case len(sp.enum) > 0:
					if stringInSlice(tempValue, sp.enum) {
						clean = append(clean, dec.Property+": "+dec.Value)
						continue
					}
				case sp.regexp != nil:
					if sp.regexp.MatchString(tempValue) {
						clean = append(clean, dec.Property+": "+dec.Value)
						continue
					}
				}
			}
		}

		if spl, ok := self.globalStyles[tempProperty]; ok {
			for _, sp := range spl {
				switch {
				case sp.handler != nil:
					if sp.handler(tempValue) {
						clean = append(clean, dec.Property+": "+dec.Value)
						continue
					}
				case len(sp.enum) > 0:
					if stringInSlice(tempValue, sp.enum) {
						clean = append(clean, dec.Property+": "+dec.Value)
						continue
					}
				case sp.regexp != nil:
					if sp.regexp.MatchString(tempValue) {
						clean = append(clean, dec.Property+": "+dec.Value)
						continue
					}
				}
			}
		}
	}

	if len(clean) > 0 {
		return strings.Join(clean, "; ")
	}
	return ""
}

// stringInSlice returns true if needle exists in haystack
func stringInSlice(needle string, haystack []string) bool {
	for _, straw := range haystack {
		if strings.EqualFold(straw, needle) {
			return true
		}
	}
	return false
}

func removeUnicode(value string) string {
	substitutedValue := value
	currentLoc := cssUnicodeChar.FindStringIndex(substitutedValue)
	for currentLoc != nil {

		character := substitutedValue[currentLoc[0]+1 : currentLoc[1]]
		character = strings.TrimSpace(character)
		if len(character) < 4 {
			character = strings.Repeat("0", 4-len(character)) + character
		} else {
			for len(character) > 4 {
				if character[0] != '0' {
					character = ""
					break
				} else {
					character = character[1:]
				}
			}
		}
		character = "\\u" + character
		translatedChar, err := strconv.Unquote(`"` + character + `"`)
		translatedChar = strings.TrimSpace(translatedChar)
		if err != nil {
			return ""
		}
		substitutedValue = substitutedValue[0:currentLoc[0]] + translatedChar +
			substitutedValue[currentLoc[1]:]
		currentLoc = cssUnicodeChar.FindStringIndex(substitutedValue)
	}
	return substitutedValue
}
