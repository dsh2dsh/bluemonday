package bluemonday

import (
	"io"
	"unsafe"

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

			hideDepth: -1,
			index:     make(map[string]int),
		},
	}
}

func (self *tokenizer) Next() html.TokenType {
	t := &self.token
	switch t.Type {
	case html.StartTagToken:
		t.pushParent()
	case html.EndTagToken:
		t.popParent()
	}

	t.Type = self.Tokenizer.Next()
	t.Reset()
	return t.Type
}

func (self *tokenizer) Token() *token {
	t := &self.token
	switch t.Type {
	case html.TextToken, html.CommentToken, html.DoctypeToken:
		t.Data = unsafeBytesToString(self.Text())

	case html.StartTagToken, html.SelfClosingTagToken, html.EndTagToken:
		name, moreAttr := self.TagName()
		t.DataAtom, t.Data = atomString(name)

		for moreAttr {
			var key, val []byte
			key, val, moreAttr = self.TagAttr()
			keyAtom, keyStr := atomString(key)
			if keyAtom == atom.Hidden {
				t.hide()
			}
			t.Attr = append(t.Attr,
				html.Attribute{Key: keyStr, Val: unsafeBytesToString(val)})
		}
	}
	return t
}

// This conversion *does not* copy data. Note that casting via
// "(string)([]byte)" *does* copy data. Also note that you *should not* change
// the byte slice after conversion, because Go strings are treated as immutable.
// This would cause a segmentation violation panic.
//
// https://www.reddit.com/r/golang/comments/14xvgoj/converting_string_byte/
func unsafeBytesToString(b []byte) string {
	return unsafe.String(unsafe.SliceData(b), len(b))
}

func atomString(b []byte) (atom.Atom, string) {
	if a := atom.Lookup(b); a != 0 {
		return a, a.String()
	}
	return 0, unsafeBytesToString(b)
}
