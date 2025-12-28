// Copyright (c) 2014, David Kitchen <david@buro9.com>
//
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// * Redistributions of source code must retain the above copyright notice, this
//   list of conditions and the following disclaimer.
//
// * Redistributions in binary form must reproduce the above copyright notice,
//   this list of conditions and the following disclaimer in the documentation
//   and/or other materials provided with the distribution.
//
// * Neither the name of the organisation (Microcosm) nor the names of its
//   contributors may be used to endorse or promote products derived from
//   this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
// FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
// OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

package bluemonday

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/url"
	"regexp"
	"slices"
	"strings"

	"golang.org/x/net/html"
	"golang.org/x/net/html/atom"
)

const genericErrMsg = "bluemonday: %w"

var (
	dataInvalidChars    = regexp.MustCompile("[A-Z;]+")
	dataURIbase64Prefix = regexp.MustCompile(`^data:[^,]*;base64,`)

	emptyURL url.URL
)

// Sanitize takes a string that contains a HTML fragment or document and applies
// the given policy allowlist.
//
// It returns a HTML string that has been sanitized by the policy or an empty
// string if an error has occurred (most likely as a consequence of extremely
// malformed input).
func (self *Policy) Sanitize(s string) string {
	if strings.TrimSpace(s) == "" {
		return s
	}
	return self.sanitizeWithBuff(strings.NewReader(s)).String()
}

// SanitizeBytes takes a []byte that contains a HTML fragment or document and
// applies the given policy allowlist.
//
// It returns a []byte containing the HTML that has been sanitized by the policy
// or an empty []byte if an error has occurred (most likely as a consequence of
// extremely malformed input).
func (self *Policy) SanitizeBytes(b []byte) []byte {
	if len(bytes.TrimSpace(b)) == 0 {
		return b
	}
	return self.sanitizeWithBuff(bytes.NewReader(b)).Bytes()
}

// SanitizeReader takes an io.Reader that contains a HTML fragment or document
// and applies the given policy allowlist.
//
// It returns a bytes.Buffer containing the HTML that has been sanitized by the
// policy. Errors during sanitization will merely return an empty result.
func (self *Policy) SanitizeReader(r io.Reader) *bytes.Buffer {
	return self.sanitizeWithBuff(r)
}

// SanitizeReaderToWriter takes an io.Reader that contains a HTML fragment or
// document and applies the given policy allowlist and writes to the provided
// writer returning an error if there is one.
func (self *Policy) SanitizeReaderToWriter(r io.Reader, w io.Writer) error {
	return self.sanitize(r, w)
}

// Performs the actual sanitization process.
func (self *Policy) sanitizeWithBuff(r io.Reader) *bytes.Buffer {
	buff := new(bytes.Buffer)
	if err := self.sanitize(r, buff); err != nil {
		return new(bytes.Buffer)
	}
	return buff
}

type stringWriter struct {
	io.Writer
}

var _ io.StringWriter = (*stringWriter)(nil)

func (a *stringWriter) WriteString(s string) (int, error) {
	return a.Write([]byte(s)) //nolint:wrapcheck // call forwarder
}

func (self *Policy) sanitize(r io.Reader, w io.Writer) error {
	// It is possible that the developer has created the policy via:
	//   p := bluemonday.Policy{}
	// rather than:
	//   p := bluemonday.NewPolicy()
	// If this is the case, and if they haven't yet triggered an action that
	// would initialize the maps, then we need to do that.
	self.init()

	buff, ok := w.(io.StringWriter)
	if !ok {
		buff = &stringWriter{w}
	}

	tokenizer := newTokenizer(r)
	for {
		t, err := nextToken(tokenizer)
		if err != nil || t == nil {
			return err
		}

		switch t.Type {
		case html.DoctypeToken:

			// DocType is not handled as there is no safe parsing mechanism
			// provided by golang.org/x/net/html for the content, and this can
			// be misused to insert HTML tags that are not then sanitized
			//
			// One might wish to recursively sanitize here using the same policy
			// but I will need to do some further testing before considering
			// this.

		case html.CommentToken:
			if err := self.commentToken(t, buff); err != nil {
				return err
			}

		case html.StartTagToken:

			if t.hidden() {
				if t.topHidden() {
					if err := self.maybeAddSpaces(buff); err != nil {
						return err
					}
				}
				continue
			}

			if !self.safeAtom(t.DataAtom) {
				t.hide()
				continue
			}

			el := self.policies(t.Data)
			if el == nil && !self.open {
				if _, ok := self.skipContent[t.Data]; ok {
					t.hide()
				} else {
					tokenizer.SkipClosingTag()
				}
				if err := self.maybeAddSpaces(buff); err != nil {
					return err
				}
				continue
			}

			self.sanitizeAttrs(t, el)
			if self.skipToken(t) {
				tokenizer.SkipClosingTag()
				if err := self.maybeAddSpaces(buff); err != nil {
					return err
				}
				break
			}

			if _, err := buff.WriteString(t.String()); err != nil {
				return fmt.Errorf(genericErrMsg, err)
			}
			self.hideSkippedContent(t)

		case html.EndTagToken:

			if t.hidden() {
				continue
			} else if tokenizer.Skipped() || !self.allowedElement(t.Data) {
				if err := self.maybeAddSpaces(buff); err != nil {
					return err
				}
				continue
			}

			if _, err := buff.WriteString(t.String()); err != nil {
				return fmt.Errorf(genericErrMsg, err)
			}

		case html.SelfClosingTagToken:

			if t.hidden() || !self.safeAtom(t.DataAtom) {
				continue
			}

			el := self.policies(t.Data)
			if el == nil && !self.open {
				if err := self.maybeAddSpaces(buff); err != nil {
					return err
				}
				continue
			}

			self.sanitizeAttrs(t, el)
			if self.skipToken(t) {
				if err := self.maybeAddSpaces(buff); err != nil {
					return err
				}
				continue
			}

			if _, err := buff.WriteString(t.String()); err != nil {
				return fmt.Errorf(genericErrMsg, err)
			}

		case html.TextToken:
			if t.hidden() {
				continue
			}
			if err := self.textToken(t, buff); err != nil {
				return err
			}
		}
	}
}

func nextToken(t *tokenizer) (*Token, error) {
	if t.Next() != html.ErrorToken {
		return t.Token(), nil
	}

	err := t.Err()
	if errors.Is(err, io.EOF) {
		// End of input means end of processing
		return nil, nil
	}
	// Raw tokenizer error
	return nil, fmt.Errorf(genericErrMsg, err)
}

func (self *Policy) commentToken(t *Token, w io.StringWriter) error {
	// Comments are ignored by default
	if !self.comments {
		return nil
	}

	// But if allowed then write the comment out as-is
	if _, err := w.WriteString(t.String()); err != nil {
		return fmt.Errorf(genericErrMsg, err)
	}
	return nil
}

func (self *Policy) maybeAddSpaces(buff io.StringWriter) error {
	if !self.addSpaces {
		return nil
	}

	if _, err := buff.WriteString(" "); err != nil {
		return fmt.Errorf(genericErrMsg, err)
	}
	return nil
}

func (self *Policy) safeAtom(a atom.Atom) bool {
	switch a {
	case atom.Script, atom.Style:
		return self.unsafe
	}
	return true
}

// sanitizeAttrs takes a set of element attribute policies and the global
// attribute policies and applies them to the []html.Attribute returning a set
// of html.Attributes that match the policies.
func (self *Policy) sanitizeAttrs(t *Token, el *element) {
	attrs := self.modifyTokenAttr(t)
	if len(attrs) == 0 {
		return
	}

	// Builds a new attribute slice based on the whether the attribute has been
	// allowed explicitly or globally.
	self.appendAttrs(t, attrs, el)

	if attrs, ok := self.setAttrs[t.Data]; ok {
		t.SetAttrs(attrs)
	}

	if len(t.Attr) == 0 {
		// If nothing was allowed, let's get out of here
		return
	}
	// t.Attr now contains the attributes that are permitted

	if linkable(t) {
		self.sanitizeLinkable(t)
	}

	switch t.DataAtom {
	case atom.Audio, atom.Img, atom.Link, atom.Script, atom.Video:
		if self.crossoriginAnonymous && len(t.Attr) > 0 {
			t.Set("crossorigin", "anonymous")
		}
	case atom.Iframe:
		if len(self.sandboxIframeAttrs) != 0 {
			self.sandboxIframe(t)
		}
	}

	self.setCondAttrs(t)
}

func (self *Policy) modifyTokenAttr(t *Token) []html.Attribute {
	if self.callbackAttr != nil {
		t.Attr = self.callbackAttr(&t.Token)
	}
	return t.reset()
}

// appendAttrs builds a new attribute slice based on the whether the attribute
// has been allowed explicitly or globally.
func (self *Policy) appendAttrs(t *Token, attrs []html.Attribute, el *element) {
	if self.open {
		t.Append(attrs...)
		return
	}

	for _, attr := range attrs {
		switch {
		// If we see a data attribute, let it through.
		case self.matchDataAttribute(t, attr):
		// Is this a "style" attribute, and if so, do we need to sanitize it?
		case self.matchStylePolicy(t, attr):
		default:
			// Is there a policy that applies?
			self.matchPolicy(t, attr, el)
		}
	}
}

func (self *Policy) matchDataAttribute(t *Token, attr html.Attribute) bool {
	if !self.dataAttributes || !dataAttribute(attr.Key) {
		return false
	}
	// If we see a data attribute, let it through.
	t.Append(attr)
	return true
}

func dataAttribute(val string) bool {
	if !strings.HasPrefix(val, "data-") {
		return false
	}

	rest, ok := strings.CutPrefix(val, "data-")
	if !ok {
		return false
	}

	// data-xml* is invalid.
	if strings.HasPrefix(rest, "xml") {
		return false
	}

	// no uppercase or semi-colons allowed.
	return !dataInvalidChars.MatchString(rest)
}

func (self *Policy) matchStylePolicy(t *Token, attr html.Attribute) bool {
	// Is this a "style" attribute, and if so, do we need to sanitize it?
	switch {
	case attr.Key != "style":
		return false
	case self.styleHandler != nil:
		attr.Val = self.styleHandler(t.Data, attr.Val)
	default:
		return false
	}

	if attr.Val != "" {
		t.Append(attr)
	}

	// We've sanitized away any and all styles; don't bother to
	// output the style attribute (even if it's allowed)
	return true
}

func (self *Policy) matchPolicy(t *Token, attr html.Attribute, el *element,
) bool {
	// Is there an element specific attribute policy that applies?
	if el.Match(attr) {
		t.Append(attr)
		return true
	}

	// Is there a global attribute policy that applies?
	if apl, ok := self.globalAttrs[attr.Key]; ok {
		for _, ap := range apl {
			if ap.Match(attr.Val) {
				t.Append(attr)
				return true
			}
		}
	}
	return false
}

func linkable(t *Token) bool {
	switch t.DataAtom {
	case atom.A, atom.Area, atom.Base, atom.Link:
		// elements that allow .href
		return true
	case atom.Blockquote, atom.Del, atom.Ins, atom.Q:
		// elements that allow .cite
		return true
	case atom.Audio, atom.Embed, atom.Iframe, atom.Img, atom.Input, atom.Script,
		atom.Source, atom.Track, atom.Video:
		// elements that allow .src
		return true
	}
	return false
}

func (self *Policy) sanitizeLinkable(t *Token) {
	var href *url.URL
	if self.parseableURLs {
		if href = self.validateURLs(t); href == nil {
			return
		}
	}

	if self.requireRelTargetBlank() {
		self.addRelTargetBlank(t, href)
	}
}

// validateURLs ensures URLs are parseable:
// - a.href
// - area.href
// - link.href
// - blockquote.cite
// - q.cite
// - img.src
// - script.src
func (self *Policy) validateURLs(t *Token) (href *url.URL) {
	switch t.DataAtom {
	case atom.A, atom.Area, atom.Base, atom.Link:
		href = self.deleteInvalidURL(t, "href")

	case atom.Blockquote, atom.Del, atom.Ins, atom.Q:
		self.deleteInvalidURL(t, "cite")

	case atom.Audio, atom.Embed, atom.Script, atom.Track:
		self.deleteInvalidURL(t, "src", self.rewriteSrc)

	case atom.Iframe:
		if src := self.deleteInvalidURL(t, "src", self.rewriteSrc); src == nil {
			t.Skip()
			return nil
		}

	case atom.Img, atom.Source:
		src := self.deleteInvalidURL(t, "src", self.rewriteSrc)
		srcsetOk := self.sanitizeSrcSet(t)
		if src == nil && !srcsetOk {
			t.Skip()
			return nil
		}

	case atom.Video:
		self.deleteInvalidURL(t, "poster", self.rewriteSrc)
		self.deleteInvalidURL(t, "src", self.rewriteSrc)
	}
	return href
}

func (self *Policy) deleteInvalidURL(t *Token, name string,
	rewriters ...func(*url.URL) *url.URL,
) *url.URL {
	attr := t.Ref(name)
	if attr == nil {
		return nil
	}

	u := self.validURL(t, attr)
	if u == nil {
		t.Delete(name)
		return nil
	}

	for _, fn := range rewriters {
		if u = fn(u); u == nil {
			t.Delete(name)
			return nil
		}
	}

	t.setURL(u)
	attr.Val = u.String()
	return u
}

func (self *Policy) validURL(t *Token, attr *html.Attribute) *url.URL {
	// URLs are valid if when space is trimmed the URL is valid
	rawurl := strings.TrimSpace(attr.Val)

	// URLs cannot contain whitespace, unless it is a data-uri
	if strings.HasPrefix(rawurl, `data:`) {
		// Remove \r and \n from base64 encoded data to pass url.Parse.
		matched := dataURIbase64Prefix.FindString(rawurl)
		if matched != "" {
			rawurl = matched + strings.ReplaceAll(
				strings.ReplaceAll(rawurl[len(matched):], "\r", ""), "\n", "")
		}
	}

	// URLs are valid if they parse
	u, err := url.Parse(rawurl)
	if err != nil {
		return nil
	}

	if !u.IsAbs() {
		if self.relativeURLs && rawurl != "" {
			return self.rewriteURL(t, attr, u)
		}
		return nil
	}

	if self.matchScheme(u) {
		return self.rewriteURL(t, attr, u)
	}
	return nil
}

func (self *Policy) matchScheme(u *url.URL) bool {
	if self.open {
		return true
	}

	if policies, ok := self.urlSchemes[u.Scheme]; ok {
		if len(policies) == 0 {
			return true
		}

		for _, fn := range policies {
			if fn(u) {
				return true
			}
		}
		return false
	}

	for _, r := range self.urlSchemeRegexps {
		if r.MatchString(u.Scheme) {
			return true
		}
	}
	return false
}

func (self *Policy) rewriteURL(t *Token, attr *html.Attribute, u *url.URL,
) *url.URL {
	if u == nil {
		return nil
	}

	if self.urlRewriter != nil {
		return self.urlRewriter(t, attr.Key, u)
	}

	if *u == emptyURL {
		return nil
	}
	return u
}

func (self *Policy) rewriteSrc(u *url.URL) *url.URL {
	if u == nil {
		return nil
	}

	if self.srcRewriter != nil {
		self.srcRewriter(u)
	}

	if *u == emptyURL {
		return nil
	}
	return u
}

func (self *Policy) sanitizeSrcSet(t *Token) bool {
	const srcset = "srcset"
	attr := t.Ref(srcset)
	if attr == nil {
		return false
	}

	images := self.parseSrcSetAttribute(t, attr)
	if len(images) == 0 {
		t.Delete(srcset)
		return false
	}

	attr.Val = images.String()
	return true
}

func (self *Policy) parseSrcSetAttribute(t *Token, attr *html.Attribute,
) ImageCandidates {
	urlParser := func(s string) *url.URL {
		a := *attr
		a.Val = s
		if u := self.rewriteSrc(self.validURL(t, &a)); u != nil {
			t.setURL(u)
			return u
		}
		return nil
	}
	return parseSrcSetAttribute(attr.Val, urlParser)
}

func (self *Policy) requireRelTargetBlank() bool {
	return self.relNoFollow ||
		self.relNoFollowAbsOnly ||
		self.relNoReferrer ||
		self.relNoReferrerAbsOnly ||
		self.targetBlank
}

func (self *Policy) addRelTargetBlank(t *Token, href *url.URL) {
	external, ok := externalLink(href, t)
	if !ok {
		return
	}

	var noopener bool
	if t.DataAtom == atom.A {
		// target="_blank" has a security risk that allows the opened window/tab to
		// issue JavaScript calls against window.opener, which in effect allow the
		// destination of the link to control the source:
		// https://dev.to/ben/the-targetblank-vulnerability-by-example
		//
		// To mitigate this risk, we need to add a specific rel attribute if it is
		// not already present: rel="noopener".
		noopener = self.setTargetBlank(t,
			external && self.targetBlank)
	}

	self.setRelAttr(t,
		self.relNoFollow || (external && self.relNoFollowAbsOnly),
		self.relNoReferrer || (external && self.relNoReferrerAbsOnly), noopener)
}

func externalLink(href *url.URL, t *Token) (bool, bool) {
	if href == nil {
		attr := t.Ref("href")
		if attr == nil {
			return false, false
		}
		u, err := url.Parse(attr.Val)
		if err != nil {
			return false, false
		}
		href = u
	}
	return href.IsAbs() || href.Hostname() != "", true
}

func (self *Policy) setTargetBlank(t *Token, required bool) bool {
	const target, blank = "target", "_blank"
	attr := t.Ref(target)

	if required {
		if attr != nil {
			attr.Val = blank
		} else {
			t.Append(html.Attribute{Key: target, Val: blank})
		}
		return true
	}

	if attr == nil {
		return false
	}
	return attr.Val == blank
}

func (self *Policy) setRelAttr(t *Token, nofollow, noreferrer, noopener bool) {
	if !nofollow && !noreferrer && !noopener {
		return
	}

	value := func() string {
		values := make([]string, 0, 3)
		if nofollow {
			values = append(values, "nofollow")
		}
		if noreferrer {
			values = append(values, "noreferrer")
		}
		if noopener {
			values = append(values, "noopener")
		}
		return strings.Join(values, " ")
	}

	const rel = "rel"
	attr := t.Ref(rel)
	if attr == nil {
		attr = t.Append(html.Attribute{Key: rel, Val: value()})
	} else if attr.Val == "" {
		attr.Val = value()
		return
	}

	for s := range strings.FieldsSeq(attr.Val) {
		switch s {
		case "nofollow":
			nofollow = false
		case "noreferrer":
			noreferrer = false
		case "noopener":
			noopener = false
		}
	}
	if !nofollow && !noreferrer && !noopener {
		return
	}
	attr.Val += " " + value()
}

func (self *Policy) skipToken(t *Token) bool {
	if t.skipped() {
		return true
	}

	if len(t.Attr) != 0 || self.open {
		return false
	}

	if _, ok := self.withoutAttrs[t.Data]; ok {
		return false
	}

	for _, r := range self.matchingWithoutAttrs {
		if r.MatchString(t.Data) {
			return false
		}
	}
	return true
}

func (self *Policy) sandboxIframe(t *Token) {
	const sandbox = "sandbox"
	attr := t.Ref(sandbox)
	if attr == nil {
		t.Append(html.Attribute{Key: sandbox})
		return
	}

	values := slices.DeleteFunc(strings.Fields(attr.Val),
		func(s string) bool {
			_, ok := self.sandboxIframeAttrs[s]
			return !ok
		})
	attr.Val = strings.Join(values, " ")
}

func (self *Policy) setCondAttrs(t *Token) {
	for _, attr := range self.setAttrsIf[t.Data] {
		attr.SetIfMatch(t)
	}
}

func (self *Policy) hideSkippedContent(t *Token) {
	switch t.DataAtom {
	case atom.Script, atom.Style:
		if self.unsafe {
			return
		}
	}

	if _, ok := self.skipContent[t.Data]; ok {
		t.hideInner()
	}
}

func (self *Policy) textToken(t *Token, w io.StringWriter) error {
	switch t.ParentAtom() {
	case atom.Script, atom.Style:
		// not encouraged, but if a policy allows JavaScript or CSS styles we
		// should not HTML escape it as that would break the output
		//
		// requires p.AllowUnsafe()
		if !self.unsafe {
			return nil
		}
		if _, err := w.WriteString(t.Data); err != nil {
			return fmt.Errorf(genericErrMsg, err)
		}
		return nil
	}

	// HTML escape the text
	if _, err := w.WriteString(t.String()); err != nil {
		return fmt.Errorf(genericErrMsg, err)
	}
	return nil
}
