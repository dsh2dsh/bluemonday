package bluemonday

import (
	"strings"

	"golang.org/x/net/html"
)

type Attribute struct {
	p    *Policy
	attr html.Attribute
	cond PolicyCond
}

type setAttrPolicy struct {
	attr html.Attribute
	cond PolicyCond
}

func (self *setAttrPolicy) SetIfMatch(t *Token) {
	if self.cond == nil || self.cond(t) {
		t.SetAttr(self.attr)
	}
}

// SetAttr says that HTML attribute with name and value must be added to
// attributes when OnElements(...) is called.
func (self *Policy) SetAttr(name, value string) *Attribute {
	self.init()
	return &Attribute{
		p:    self,
		attr: html.Attribute{Key: strings.ToLower(name), Val: value},
	}
}

// SetAttrIf sets that HTML attribute with given name and value must be added to
// attributes when OnElements(...) is called, if given cond evaluates to true.
// If it evaluates to false, this policy does nothing.
func (self *Policy) SetAttrIf(name, value string, cond PolicyCond) *Attribute {
	return self.SetAttr(name, value).withCond(cond)
}

func (self *Attribute) withCond(cond PolicyCond) *Attribute {
	self.cond = cond
	return self
}

// OnElements will set attribute on a given range of HTML elements and return
// the updated policy
func (self *Attribute) OnElements(names ...string) *Policy {
	if self.attr.Key == "" {
		return self.p
	}

	if self.cond == nil {
		for _, name := range names {
			name = strings.ToLower(name)
			self.p.setAttrs[name] = append(self.p.setAttrs[name], self.attr)
		}
		return self.p
	}

	ap := &setAttrPolicy{attr: self.attr, cond: self.cond}
	for _, name := range names {
		name = strings.ToLower(name)
		self.p.setAttrsIf[name] = append(self.p.setAttrsIf[name], ap)
	}
	return self.p
}
