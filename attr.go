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

func (self *setAttrPolicy) Match(t *token) bool {
	return self.cond == nil || self.cond(t)
}

// SetAttr says that HTML attribute with name and value must be added to
// attributes when OnElements(...) is called.
func (p *Policy) SetAttr(name, value string) Attribute {
	p.init()
	return Attribute{
		p:    p,
		attr: html.Attribute{Key: strings.ToLower(name), Val: value},
	}
}

// SetAttrIf sets that HTML attribute with given name and value must be added to
// attributes when OnElements(...) is called, if given cond evaluates to true.
// If it evaluates to false, this policy does nothing.
func (p *Policy) SetAttrIf(name, value string, cond PolicyCond) Attribute {
	return p.SetAttr(name, value).withCond(cond)
}

func (self Attribute) withCond(cond PolicyCond) Attribute {
	self.cond = cond
	return self
}

// OnElements will set attribute on a given range of HTML elements and return
// the updated policy
func (self Attribute) OnElements(elements ...string) *Policy {
	if self.attr.Key == "" {
		return self.p
	}

	for _, element := range elements {
		element = strings.ToLower(element)
		switch self.cond {
		case nil:
			self.p.setAttrs[element] = append(self.p.setAttrs[element], self.attr)
		default:
			self.p.setAttrsIf[element] = append(self.p.setAttrsIf[element],
				setAttrPolicy{
					attr: self.attr,
					cond: self.cond,
				})
		}
	}
	return self.p
}
