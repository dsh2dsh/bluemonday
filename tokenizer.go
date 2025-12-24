package bluemonday

import (
	"io"

	"golang.org/x/net/html"
	"golang.org/x/net/html/atom"
)

type tokenizer struct {
	*html.Tokenizer

	token token
}

func newTokenizer(r io.Reader) *tokenizer {
	return &tokenizer{
		Tokenizer: html.NewTokenizer(r),
		token: token{
			Token: html.Token{Attr: []html.Attribute{}},
			index: make(map[string]int),
		},
	}
}

func (self *tokenizer) Next() html.TokenType {
	t := &self.token
	t.Type = self.Tokenizer.Next()
	t.Reset()
	return t.Type
}

func (self *tokenizer) Token() *token {
	t := &self.token
	switch t.Type {
	case html.TextToken, html.CommentToken, html.DoctypeToken:
		t.Data = string(self.Text())
	case html.StartTagToken, html.SelfClosingTagToken, html.EndTagToken:
		name, moreAttr := self.TagName()
		for moreAttr {
			var key, val []byte
			key, val, moreAttr = self.TagAttr()
			keyStr := atom.String(key)
			if keyStr == "hidden" {
				t.Hide()
			}
			t.Attr = append(t.Attr,
				html.Attribute{Key: keyStr, Val: string(val)})
		}
		if a := atom.Lookup(name); a != 0 {
			t.DataAtom, t.Data = a, a.String()
		} else {
			t.DataAtom, t.Data = 0, string(name)
		}
	}
	return t
}
