package bluemonday

import (
	"net/url"
	"slices"

	"golang.org/x/net/html"
	"golang.org/x/net/html/atom"
)

// Section 12.1.2, "Elements", gives this list of void elements. Void elements
// are those that can't have any contents.
//
// Copied from golang.org/x/net/html/render.go
//
// See also https://developer.mozilla.org/en-US/docs/Glossary/Void_element
var voidElements = map[atom.Atom]bool{
	atom.Area:   true,
	atom.Base:   true,
	atom.Br:     true,
	atom.Col:    true,
	atom.Embed:  true,
	atom.Hr:     true,
	atom.Img:    true,
	atom.Input:  true,
	atom.Keygen: true, // "keygen" has been removed from the spec, but are kept here for backwards compatibility.
	atom.Link:   true,
	atom.Meta:   true,
	atom.Param:  true,
	atom.Source: true,
	atom.Track:  true,
	atom.Wbr:    true,
}

type Token struct {
	html.Token

	parents   []atom.Atom
	hideDepth int
	skip      bool

	index map[string]int
	u     *url.URL
}

func (self *Token) pushParent() {
	self.parents = append(self.parents, self.DataAtom)
}

func (self *Token) popParent() {
	if len(self.parents) == 0 {
		return
	}

	last := len(self.parents) - 1
	for ; last >= 0; last-- {
		if self.parents[last] == self.DataAtom {
			self.parents = self.parents[:last]
			break
		}
	}

	if self.topHidden() {
		self.hideDepth = -1
	}
}

func (self *Token) depth() int { return len(self.parents) }

func (self *Token) hide()      { self.hideDepth = len(self.parents) }
func (self *Token) hideInner() { self.hideDepth = len(self.parents) + 1 }

func (self *Token) hidden() bool {
	switch {
	case self.hideDepth == -1:
		return false
	case self.Type == html.EndTagToken:
		return len(self.parents) > self.hideDepth
	}
	return len(self.parents) >= self.hideDepth
}

func (self *Token) topHidden() bool {
	return len(self.parents) == self.hideDepth
}

func (self *Token) hasParent() bool {
	for i := len(self.parents) - 1; i >= 0; i-- {
		if self.DataAtom == self.parents[i] {
			return true
		}
	}
	return false
}

func (self *Token) withComputedType() *Token {
	if self.Type == html.StartTagToken && self.voidElement() {
		self.Type = html.SelfClosingTagToken
	}
	return self
}

func (self *Token) voidElement() bool {
	if self.DataAtom == 0 {
		return false
	}
	return voidElements[self.DataAtom]
}

func (self *Token) reset() []html.Attribute {
	attrs := self.Attr
	self.Attr = self.Attr[:0]
	clear(self.index)
	self.u = nil
	self.skip = false
	return attrs
}

func (self *Token) setURL(u *url.URL) { self.u = u }
func (self *Token) url() *url.URL     { return self.u }

func (self *Token) skipped() bool { return self.skip }

// ParentAtom returns parent of this token.
func (self *Token) ParentAtom() atom.Atom {
	if len(self.parents) == 0 {
		return 0
	}
	return self.parents[len(self.parents)-1]
}

// Append appends given attributes to attribute list of this token.
func (self *Token) Append(attrs ...html.Attribute) *html.Attribute {
	i := len(self.Attr)
	for _, attr := range attrs {
		self.index[attr.Key] = i
		i++
	}
	self.Attr = append(self.Attr, attrs...)
	return &self.Attr[len(self.Attr)-1]
}

// Delete deletes an attribute from attribute list of this token.
func (self *Token) Delete(key string) {
	i, ok := self.index[key]
	if !ok {
		return
	}

	self.Attr = slices.Delete(self.Attr, i, i+1)
	delete(self.index, key)

	for ; i < len(self.Attr); i++ {
		key := self.Attr[i].Key
		if _, ok := self.index[key]; ok {
			self.index[key]--
		}
	}
}

// Ref returns reference to an attribute from attribute list of this element.
func (self *Token) Ref(key string) *html.Attribute {
	if i, ok := self.index[key]; ok {
		return &self.Attr[i]
	}
	return nil
}

// Set changes value of an attribute if it exists or appends a new one.
func (self *Token) Set(key, val string) {
	self.SetAttr(html.Attribute{Key: key, Val: val})
}

// SetAttr changes value of an attribute if it exists or appends a new one.
func (self *Token) SetAttr(attr html.Attribute) {
	if i, ok := self.index[attr.Key]; ok {
		self.Attr[i] = attr
		return
	}
	self.Append(attr)
}

// SetAttrs changes values of multiple attributes or appends any of them which
// not exists.
func (self *Token) SetAttrs(attrs []html.Attribute) {
	var n int
	for _, attr := range attrs {
		if i, ok := self.index[attr.Key]; ok {
			self.Attr[i].Val = attr.Val
		} else {
			n++
		}
	}

	if n == 0 {
		return
	}

	self.Attr = slices.Grow(self.Attr, n)
	if n == len(attrs) {
		self.Append(attrs...)
		return
	}

	for _, attr := range attrs {
		if _, ok := self.index[attr.Key]; !ok {
			self.Append(attr)
		}
	}
}

// Skip strips this token from output.
func (self *Token) Skip() { self.skip = true }
