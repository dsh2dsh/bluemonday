package css

import (
	"regexp"
	"strings"
)

type PolicyBuilder struct {
	p *Policy

	propertyNames []string
	regexp        *regexp.Regexp
	enum          []string
	handler       func(string) bool
}

func NewPolicyBuilder(p *Policy, propertyNames ...string) *PolicyBuilder {
	b := &PolicyBuilder{
		p: p,

		propertyNames: make([]string, len(propertyNames)),
	}

	for i, propertyName := range propertyNames {
		b.propertyNames[i] = strings.ToLower(propertyName)
	}
	return b
}

// Matching allows a regular expression to be applied to a nascent style policy,
// and returns the style policy.
func (self *PolicyBuilder) Matching(regex *regexp.Regexp) *PolicyBuilder {
	self.regexp = regex
	return self
}

// MatchingEnum allows a list of allowed values to be applied to a nascent style
// policy, and returns the style policy.
func (self *PolicyBuilder) MatchingEnum(enum ...string) *PolicyBuilder {
	self.enum = enum
	return self
}

// MatchingHandler allows a handler to be applied to a nascent style policy, and
// returns the style policy.
func (self *PolicyBuilder) MatchingHandler(handler func(string) bool,
) *PolicyBuilder {
	self.handler = handler
	return self
}

// OnElements will bind a style policy to a given range of HTML elements and
// return the updated policy.
func (self *PolicyBuilder) OnElements(elements ...string) *Policy {
	for _, element := range elements {
		element = strings.ToLower(element)

		for _, attr := range self.propertyNames {
			if _, ok := self.p.elsAndStyles[element]; !ok {
				self.p.elsAndStyles[element] = make(map[string][]stylePolicy)
			}
			sp := self.stylePolicy(attr)
			self.p.elsAndStyles[element][attr] = append(
				self.p.elsAndStyles[element][attr], sp)
		}
	}
	return self.p
}

// OnElementsMatching will bind a style policy to any HTML elements matching the
// pattern and return the updated policy.
func (self *PolicyBuilder) OnElementsMatching(regex *regexp.Regexp) *Policy {
	if _, ok := self.p.elsMatchingAndStyles[regex]; !ok {
		self.p.elsMatchingAndStyles[regex] = make(map[string][]stylePolicy)
	}

	for _, attr := range self.propertyNames {
		sp := self.stylePolicy(attr)
		self.p.elsMatchingAndStyles[regex][attr] = append(
			self.p.elsMatchingAndStyles[regex][attr], sp)
	}
	return self.p
}

func (self *PolicyBuilder) stylePolicy(attr string) stylePolicy {
	sp := stylePolicy{}
	switch {
	case self.handler != nil:
		sp.handler = self.handler
	case len(self.enum) > 0:
		sp.enum = self.enum
	case self.regexp != nil:
		sp.regexp = self.regexp
	default:
		sp.handler = GetDefaultHandler(attr)
	}
	return sp
}

// Globally will bind a style policy to all HTML elements and return the updated
// policy.
func (self *PolicyBuilder) Globally() *Policy {
	for _, attr := range self.propertyNames {
		if _, ok := self.p.globalStyles[attr]; !ok {
			self.p.globalStyles[attr] = []stylePolicy{}
		}

		// Use only one strategy for validating styles, fallback to default.
		sp := self.stylePolicy(attr)
		self.p.globalStyles[attr] = append(self.p.globalStyles[attr], sp)
	}
	return self.p
}
