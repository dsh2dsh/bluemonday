package bluemonday

import (
	"slices"

	"golang.org/x/net/html"
)

type token struct {
	html.Token

	index map[string]int
}

func (self *token) Append(attr html.Attribute) *html.Attribute {
	i := len(self.Attr)
	self.index[attr.Key] = i
	self.Attr = append(self.Attr, attr)
	return &self.Attr[i]
}

func (self *token) Contains(key string) bool {
	return slices.ContainsFunc(self.Attr, func(a html.Attribute) bool {
		return a.Key == key
	})
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
	return attrs
}

func (self *token) Set(key, val string) {
	if i, ok := self.index[key]; ok {
		self.Attr[i].Val = val
		return
	}
	self.Append(html.Attribute{Key: key, Val: val})
}
