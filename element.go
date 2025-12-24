package bluemonday

import (
	"maps"
	"regexp"
	"slices"

	"golang.org/x/net/html"
)

func (self *Policy) allowElement(name string) {
	if _, ok := self.elements[name]; !ok {
		self.elements[name] = &element{}
	}
}

func (self *Policy) allowMatching(re *regexp.Regexp) {
	if _, ok := self.matchingElements[re]; !ok {
		self.matchingElements[re] = &element{}
	}
}

func (self *Policy) appendElement(name, attr string, ap *attrPolicy) {
	switch policies, ok := self.elements[name]; {
	case ok:
		policies.Append(attr, ap)
	default:
		policies = &element{}
		policies.Append(attr, ap)
		self.elements[name] = policies
	}
}

func (self *Policy) appendMatching(re *regexp.Regexp, attr string,
	ap *attrPolicy,
) {
	switch policies, ok := self.matchingElements[re]; {
	case ok:
		policies.Append(attr, ap)
	default:
		policies = &element{}
		policies.Append(attr, ap)
		self.matchingElements[re] = policies
	}
}

func (self *Policy) deleteElementAttrs(name string, attrs ...string) {
	policies, ok := self.elements[name]
	if !ok {
		return
	}
	for _, attr := range attrs {
		policies.Delete(attr)
	}
}

func (self *Policy) policies(name string) (el *element) {
	el, ok := self.elements[name]
	if ok {
		return el
	}

	var multipleMatches bool
	for re, el2 := range self.matchingElements {
		switch {
		case !re.MatchString(name):
			continue
		case el == nil:
			el = el2
		case !multipleMatches:
			el = el.Clone()
			multipleMatches = true
			fallthrough
		default:
			el.Merge(el2)
		}
	}
	return el
}

func (self *Policy) allowedElement(name string) bool {
	if self.open {
		return true
	}

	if _, ok := self.elements[name]; ok {
		return true
	}

	for re := range self.matchingElements {
		if re.MatchString(name) {
			return true
		}
	}
	return false
}

type element struct {
	attrs map[string][]*attrPolicy
}

func (self *element) Append(name string, ap *attrPolicy) {
	if self.attrs == nil {
		self.attrs = map[string][]*attrPolicy{name: {ap}}
		return
	}

	if _, ok := self.attrs[name]; ok {
		self.attrs[name] = append(self.attrs[name], ap)
		return
	}
	self.attrs[name] = []*attrPolicy{ap}
}

func (self *element) Clone() *element {
	return &element{attrs: maps.Clone(self.attrs)}
}

func (self *element) Delete(name string) { delete(self.attrs, name) }

func (self *element) Match(attr html.Attribute) bool {
	if self.attrs == nil {
		return false
	}

	policies, ok := self.attrs[attr.Key]
	if !ok {
		return false
	}

	for _, ap := range policies {
		if ap.Match(attr.Val) {
			return true
		}
	}
	return false
}

func (self *element) Merge(el2 *element) {
	if self.attrs == nil {
		self.attrs = maps.Clone(el2.attrs)
		return
	}

	for attr, policies := range el2.attrs {
		if _, ok := self.attrs[attr]; ok {
			self.attrs[attr] = append(self.attrs[attr], policies...)
		} else {
			self.attrs[attr] = slices.Clone(policies)
		}
	}
}
