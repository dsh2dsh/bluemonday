package bluemonday

import (
	"regexp"
	"strconv"
	"strings"

	"github.com/aymerick/douceur/parser"
	"golang.org/x/net/html"
)

var cssUnicodeChar = regexp.MustCompile(`\\[0-9a-f]{1,6} ?`)

func (p *Policy) hasStylePolicies(elementName string) bool {
	if len(p.globalStyles) > 0 {
		return true
	}

	sps, elementHasStylePolicies := p.elsAndStyles[elementName]
	if elementHasStylePolicies && len(sps) > 0 {
		return true
	}

	// no specific element policy found, look for a pattern match
	for k, v := range p.elsMatchingAndStyles {
		if k.MatchString(elementName) && len(v) > 0 {
			return true
		}
	}
	return false
}

func (p *Policy) sanitizeStyles(attr *html.Attribute, elementName string) {
	sps := p.elsAndStyles[elementName]
	if len(sps) == 0 {
		sps = map[string][]stylePolicy{}
		// check for any matching elements, if we don't already have a policy found
		// if multiple matches are found they will be overwritten, it's best
		// to not have overlapping matchers
		for regex, policies := range p.elsMatchingAndStyles {
			if regex.MatchString(elementName) {
				for k, v := range policies {
					sps[k] = append(sps[k], v...)
				}
			}
		}
	}

	// Add semi-colon to end to fix parsing issue
	attr.Val = strings.TrimRight(attr.Val, " ")
	if len(attr.Val) > 0 && attr.Val[len(attr.Val)-1] != ';' {
		attr.Val += ";"
	}
	decs, err := parser.ParseDeclarations(attr.Val)
	if err != nil {
		attr.Val = ""
		return
	}
	clean := []string{}
	prefixes := []string{"-webkit-", "-moz-", "-ms-", "-o-", "mso-", "-xv-", "-atsc-", "-wap-", "-khtml-", "prince-", "-ah-", "-hp-", "-ro-", "-rim-", "-tc-"}

decLoop:
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
						continue decLoop
					}
				case len(sp.enum) > 0:
					if stringInSlice(tempValue, sp.enum) {
						clean = append(clean, dec.Property+": "+dec.Value)
						continue decLoop
					}
				case sp.regexp != nil:
					if sp.regexp.MatchString(tempValue) {
						clean = append(clean, dec.Property+": "+dec.Value)
						continue decLoop
					}
				}
			}
		}
		if spl, ok := p.globalStyles[tempProperty]; ok {
			for _, sp := range spl {
				switch {
				case sp.handler != nil:
					if sp.handler(tempValue) {
						clean = append(clean, dec.Property+": "+dec.Value)
						continue decLoop
					}
				case len(sp.enum) > 0:
					if stringInSlice(tempValue, sp.enum) {
						clean = append(clean, dec.Property+": "+dec.Value)
						continue decLoop
					}
				case sp.regexp != nil:
					if sp.regexp.MatchString(tempValue) {
						clean = append(clean, dec.Property+": "+dec.Value)
						continue decLoop
					}
				}
			}
		}
	}
	if len(clean) > 0 {
		attr.Val = strings.Join(clean, "; ")
	} else {
		attr.Val = ""
	}
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
		substitutedValue = substitutedValue[0:currentLoc[0]] + translatedChar + substitutedValue[currentLoc[1]:]
		currentLoc = cssUnicodeChar.FindStringIndex(substitutedValue)
	}
	return substitutedValue
}
