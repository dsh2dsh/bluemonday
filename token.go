package bluemonday

import (
	"net/url"
	"slices"

	"golang.org/x/net/html"
	"golang.org/x/net/html/atom"
)

type token struct {
	html.Token

	parents   []atom.Atom
	hideDepth int
	skip      bool

	index map[string]int
	u     *url.URL
}

func (self *token) pushParent() {
	self.parents = append(self.parents, self.DataAtom)
}

func (self *token) popParent() {
	if len(self.parents) == 0 {
		return
	}

	last := len(self.parents) - 1
	self.parents = self.parents[:last]

	if self.topHidden() {
		self.hideDepth = -1
	}
}

func (self *token) hide()      { self.hideDepth = len(self.parents) }
func (self *token) hideInner() { self.hideDepth = len(self.parents) + 1 }

func (self *token) hidden() bool {
	switch {
	case self.hideDepth == -1:
		return false
	case self.Type == html.EndTagToken:
		return len(self.parents) > self.hideDepth
	}
	return len(self.parents) >= self.hideDepth
}

func (self *token) topHidden() bool {
	return len(self.parents) == self.hideDepth
}

func (self *token) ParentAtom() atom.Atom {
	if len(self.parents) == 0 {
		return 0
	}
	return self.parents[len(self.parents)-1]
}

func (self *token) Append(attrs ...html.Attribute) *html.Attribute {
	i := len(self.Attr)
	for _, attr := range attrs {
		self.index[attr.Key] = i
		i++
	}
	self.Attr = append(self.Attr, attrs...)
	return &self.Attr[len(self.Attr)-1]
}

func (self *token) MakeIndex() {
	for i, attr := range self.Attr {
		self.index[attr.Key] = i
	}
}

func (self *token) Delete(key string) {
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

func (self *token) Ref(key string) *html.Attribute {
	if i, ok := self.index[key]; ok {
		return &self.Attr[i]
	}
	return nil
}

func (self *token) Reset() []html.Attribute {
	attrs := self.Attr
	self.Attr = self.Attr[:0]
	clear(self.index)
	self.u = nil
	self.skip = false
	return attrs
}

func (self *token) Set(key, val string) {
	self.SetAttr(html.Attribute{Key: key, Val: val})
}

func (self *token) SetAttr(attr html.Attribute) {
	if i, ok := self.index[attr.Key]; ok {
		self.Attr[i] = attr
		return
	}
	self.Append(attr)
}

func (self *token) SetAttrs(attrs []html.Attribute) {
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

func (self *token) SetURL(u *url.URL) { self.u = u }
func (self *token) URL() *url.URL     { return self.u }

func (self *token) Skip()         { self.skip = true }
func (self *token) Skipped() bool { return self.skip }
