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
)

// Sanitize takes a string that contains a HTML fragment or document and applies
// the given policy allowlist.
//
// It returns a HTML string that has been sanitized by the policy or an empty
// string if an error has occurred (most likely as a consequence of extremely
// malformed input).
func (p *Policy) Sanitize(s string) string {
	if strings.TrimSpace(s) == "" {
		return s
	}
	return p.sanitizeWithBuff(strings.NewReader(s)).String()
}

// SanitizeBytes takes a []byte that contains a HTML fragment or document and
// applies the given policy allowlist.
//
// It returns a []byte containing the HTML that has been sanitized by the policy
// or an empty []byte if an error has occurred (most likely as a consequence of
// extremely malformed input).
func (p *Policy) SanitizeBytes(b []byte) []byte {
	if len(bytes.TrimSpace(b)) == 0 {
		return b
	}
	return p.sanitizeWithBuff(bytes.NewReader(b)).Bytes()
}

// SanitizeReader takes an io.Reader that contains a HTML fragment or document
// and applies the given policy allowlist.
//
// It returns a bytes.Buffer containing the HTML that has been sanitized by the
// policy. Errors during sanitization will merely return an empty result.
func (p *Policy) SanitizeReader(r io.Reader) *bytes.Buffer {
	return p.sanitizeWithBuff(r)
}

// SanitizeReaderToWriter takes an io.Reader that contains a HTML fragment or
// document and applies the given policy allowlist and writes to the provided
// writer returning an error if there is one.
func (p *Policy) SanitizeReaderToWriter(r io.Reader, w io.Writer) error {
	return p.sanitize(r, w)
}

// Performs the actual sanitization process.
func (p *Policy) sanitizeWithBuff(r io.Reader) *bytes.Buffer {
	buff := new(bytes.Buffer)
	if err := p.sanitize(r, buff); err != nil {
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

func (p *Policy) sanitize(r io.Reader, w io.Writer) error {
	// It is possible that the developer has created the policy via:
	//   p := bluemonday.Policy{}
	// rather than:
	//   p := bluemonday.NewPolicy()
	// If this is the case, and if they haven't yet triggered an action that
	// would initialize the maps, then we need to do that.
	p.init()

	buff, ok := w.(io.StringWriter)
	if !ok {
		buff = &stringWriter{w}
	}

	var (
		hidden               int64
		skipElementContent   bool
		skipClosingTag       []string
		recentlyStartedToken atom.Atom
	)

	tokenizer := newTokenizer(r)
	for {
		if tokenizer.Next() == html.ErrorToken {
			err := tokenizer.Err()
			if errors.Is(err, io.EOF) {
				// End of input means end of processing
				return nil
			}
			// Raw tokenizer error
			return fmt.Errorf(genericErrMsg, err)
		}

		t := tokenizer.Token()
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

			// Comments are ignored by default
			if p.allowComments {
				// But if allowed then write the comment out as-is
				if _, err := buff.WriteString(t.String()); err != nil {
					return fmt.Errorf(genericErrMsg, err)
				}
			}

		case html.StartTagToken:

			if hidden > 0 {
				hidden++
				continue
			} else if t.Contains("hidden") {
				hidden++
				skipElementContent = true
				if err := p.maybeAddSpaces(buff); err != nil {
					return err
				}
				continue
			}

			recentlyStartedToken = t.DataAtom
			switch t.DataAtom {
			case atom.Script, atom.Style:
				if !p.allowUnsafe {
					continue
				}
			}

			aps, ok := p.elsAndAttrs[t.Data]
			if !ok {
				aa := p.matchRegex(t.Data)
				if aa == nil {
					if _, ok := p.setOfElementsToSkipContent[t.Data]; ok {
						hidden++
						skipElementContent = true
					}
					if err := p.maybeAddSpaces(buff); err != nil {
						return err
					}
					continue
				}
				aps = aa
			}

			p.sanitizeAttrs(t, aps)
			if p.skipToken(t) {
				skipClosingTag = append(skipClosingTag, t.Data)
				if err := p.maybeAddSpaces(buff); err != nil {
					return err
				}
				break
			}

			if skipElementContent {
				continue
			} else if _, err := buff.WriteString(t.String()); err != nil {
				return fmt.Errorf(genericErrMsg, err)
			}

			switch t.DataAtom {
			case atom.Script, atom.Style:
			default:
				if _, ok := p.setOfElementsToSkipContent[t.Data]; ok {
					skipElementContent = true
				}
			}

		case html.EndTagToken:

			if hidden > 0 {
				hidden--
				if hidden == 0 {
					skipElementContent = false
					if err := p.maybeAddSpaces(buff); err != nil {
						return err
					}
				}
				continue
			}

			if recentlyStartedToken == t.DataAtom {
				recentlyStartedToken = 0
			}

			switch t.DataAtom {
			case atom.Script, atom.Style:
				if !p.allowUnsafe {
					continue
				}
			}

			if len(skipClosingTag) != 0 && skipClosingTag[len(skipClosingTag)-1] == t.Data {
				skipClosingTag = skipClosingTag[:len(skipClosingTag)-1]
				if err := p.maybeAddSpaces(buff); err != nil {
					return err
				}
				break
			}

			if _, ok := p.elsAndAttrs[t.Data]; !ok {
				var match bool
				for regex := range p.elsMatchingAndAttrs {
					if regex.MatchString(t.Data) {
						match = true
						break
					}
				}
				if !match {
					if err := p.maybeAddSpaces(buff); err != nil {
						return err
					}
					break
				}
			}

			switch t.DataAtom {
			case atom.Script, atom.Style:
			default:
				_, ok := p.setOfElementsToSkipContent[t.Data]
				if skipElementContent && ok {
					skipElementContent = false
				}
			}

			if !skipElementContent {
				if _, err := buff.WriteString(t.String()); err != nil {
					return fmt.Errorf(genericErrMsg, err)
				}
			}

		case html.SelfClosingTagToken:

			if hidden > 0 {
				continue
			}

			switch t.DataAtom {
			case atom.Script, atom.Style:
				if !p.allowUnsafe {
					continue
				}
			}

			aps, ok := p.elsAndAttrs[t.Data]
			if !ok {
				aa := p.matchRegex(t.Data)
				if aa == nil {
					if err := p.maybeAddSpaces(buff); err != nil {
						return err
					}
					break
				}
				aps = aa
			}

			p.sanitizeAttrs(t, aps)
			if p.skipToken(t) {
				if err := p.maybeAddSpaces(buff); err != nil {
					return err
				}
				break
			}

			if !skipElementContent {
				if _, err := buff.WriteString(t.String()); err != nil {
					return fmt.Errorf(genericErrMsg, err)
				}
			}

		case html.TextToken:

			if skipElementContent {
				continue
			}

			switch recentlyStartedToken {
			case atom.Script, atom.Style:
				// not encouraged, but if a policy allows JavaScript or CSS styles we
				// should not HTML escape it as that would break the output
				//
				// requires p.AllowUnsafe()
				if p.allowUnsafe {
					if _, err := buff.WriteString(t.Data); err != nil {
						return fmt.Errorf(genericErrMsg, err)
					}
				}
			default:
				// HTML escape the text
				if _, err := buff.WriteString(t.String()); err != nil {
					return fmt.Errorf(genericErrMsg, err)
				}
			}

		default:
			// A token that didn't exist in the html package when we wrote this
			return fmt.Errorf("bluemonday: unknown token: %v", t)
		}
	}
}

func (p *Policy) maybeAddSpaces(buff io.StringWriter) error {
	if !p.addSpaces {
		return nil
	}

	if _, err := buff.WriteString(" "); err != nil {
		return fmt.Errorf(genericErrMsg, err)
	}
	return nil
}

// sanitizeAttrs takes a set of element attribute policies and the global
// attribute policies and applies them to the []html.Attribute returning a set
// of html.Attributes that match the policies.
func (p *Policy) sanitizeAttrs(t *token, aps map[string][]attrPolicy) {
	attrs := p.modifyTokenAttr(t)
	if len(attrs) == 0 {
		return
	}

	// Builds a new attribute slice based on the whether the attribute has been
	// allowed explicitly or globally.
	for _, attr := range attrs {
		switch {
		// If we see a data attribute, let it through.
		case p.matchDataAttribute(t, attr):
		// Is this a "style" attribute, and if so, do we need to sanitize it?
		case p.matchStylePolicy(t, attr):
		default:
			// Is there a policy that applies?
			p.matchPolicy(t, attr, aps)
		}
	}

	if attrs, ok := p.setAttrs[t.Data]; ok {
		t.SetAttrs(attrs)
	}

	if len(t.Attr) == 0 {
		// If nothing was allowed, let's get out of here
		return
	}
	// t.Attr now contains the attributes that are permitted

	if linkable(t) {
		p.sanitizeLinkable(t)
	}

	switch t.DataAtom {
	case atom.Audio, atom.Img, atom.Link, atom.Script, atom.Video:
		if p.requireCrossOriginAnonymous && len(t.Attr) > 0 {
			t.Set("crossorigin", "anonymous")
		}
	case atom.Iframe:
		if len(p.requireSandboxOnIFrame) != 0 {
			p.sandboxIframe(t)
		}
	}
}

func (p *Policy) modifyTokenAttr(t *token) []html.Attribute {
	if p.callbackAttr != nil {
		t.Attr = p.callbackAttr(&t.Token)
	}
	return t.Reset()
}

func (p *Policy) matchDataAttribute(t *token, attr html.Attribute) bool {
	if !p.allowDataAttributes || !dataAttribute(attr.Key) {
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

func (p *Policy) matchStylePolicy(t *token, attr html.Attribute) bool {
	// Is this a "style" attribute, and if so, do we need to sanitize it?
	if attr.Key != "style" || !p.hasStylePolicies(t.Data) {
		return false
	}

	p.sanitizeStyles(&attr, t.Data)
	if attr.Val != "" {
		t.Append(attr)
	}
	// We've sanitized away any and all styles; don't bother to
	// output the style attribute (even if it's allowed)
	return true
}

func (p *Policy) matchPolicy(t *token, attr html.Attribute,
	aps map[string][]attrPolicy,
) bool {
	// Is there an element specific attribute policy that applies?
	if apl, ok := aps[attr.Key]; ok {
		for _, ap := range apl {
			if ap.Match(attr.Val) {
				t.Append(attr)
				return true
			}
		}
	}

	// Is there a global attribute policy that applies?
	if apl, ok := p.globalAttrs[attr.Key]; ok {
		for _, ap := range apl {
			if ap.Match(attr.Val) {
				t.Append(attr)
				return true
			}
		}
	}
	return false
}

func linkable(t *token) bool {
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

func (p *Policy) sanitizeLinkable(t *token) {
	var href *url.URL
	if p.requireParseableURLs {
		if href = p.validateURLs(t); href == nil {
			return
		}
	}

	if p.requireRelTargetBlank() {
		p.addRelTargetBlank(t, href)
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
func (p *Policy) validateURLs(t *token) (href *url.URL) {
	switch t.DataAtom {
	case atom.A, atom.Area, atom.Base, atom.Link:
		href = p.deleteInvalidURL(t, "href")

	case atom.Blockquote, atom.Del, atom.Ins, atom.Q:
		p.deleteInvalidURL(t, "cite")

	case atom.Audio, atom.Embed, atom.Iframe, atom.Script, atom.Track:
		p.deleteInvalidURL(t, "src", p.rewriteSrc)

	case atom.Img, atom.Source:
		src := p.deleteInvalidURL(t, "src", p.rewriteSrc)
		srcsetOk := p.sanitizeSrcSet(t)
		if src == nil && !srcsetOk {
			t.Reset()
			return nil
		}

	case atom.Video:
		p.deleteInvalidURL(t, "poster", p.rewriteSrc)
		p.deleteInvalidURL(t, "src", p.rewriteSrc)
	}
	return href
}

func (p *Policy) deleteInvalidURL(t *token, name string,
	rewriters ...func(*url.URL) *url.URL,
) *url.URL {
	attr := t.Ref(name)
	if attr == nil {
		return nil
	}

	u := p.validURL(attr.Val)
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

	attr.Val = u.String()
	return u
}

func (p *Policy) validURL(rawurl string) *url.URL {
	// URLs are valid if when space is trimmed the URL is valid
	rawurl = strings.TrimSpace(rawurl)

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
		if p.allowRelativeURLs && rawurl != "" {
			return p.rewriteURL(u)
		}
		return nil
	}

	urlPolicies, ok := p.allowURLSchemes[u.Scheme]
	if !ok {
		for _, r := range p.allowURLSchemeRegexps {
			if r.MatchString(u.Scheme) {
				return p.rewriteURL(u)
			}
		}
		return nil
	}

	if len(urlPolicies) == 0 {
		return p.rewriteURL(u)
	}

	for _, urlPolicy := range urlPolicies {
		if urlPolicy(u) {
			return p.rewriteURL(u)
		}
	}
	return nil
}

func (p *Policy) rewriteURL(u *url.URL) *url.URL {
	if p.urlRewriter != nil {
		p.urlRewriter(u)
	}

	var empty url.URL
	if *u == empty {
		return nil
	}
	return u
}

func (p *Policy) rewriteSrc(u *url.URL) *url.URL {
	if p.srcRewriter != nil {
		p.srcRewriter(u)
	}

	var empty url.URL
	if *u == empty {
		return nil
	}
	return u
}

func (p *Policy) sanitizeSrcSet(t *token) bool {
	const srcset = "srcset"
	attr := t.Ref(srcset)
	if attr == nil {
		return false
	}

	images := p.parseSrcSetAttribute(attr.Val)
	if len(images) == 0 {
		t.Delete(srcset)
		return false
	}

	var removed int
	for _, img := range images {
		if u := p.rewriteSrc(img.URL()); u == nil {
			removed++
			img.ImageURL = ""
		}
	}

	if removed == len(images) {
		t.Delete(srcset)
		return false
	} else if removed > 0 {
		images = slices.DeleteFunc(images, func(img *imageCandidate) bool {
			return img.ImageURL == ""
		})
		if len(images) == 0 {
			t.Delete(srcset)
			return false
		}
	}

	attr.Val = images.String()
	return true
}

func (p *Policy) requireRelTargetBlank() bool {
	return p.requireNoFollow ||
		p.requireNoFollowFullyQualifiedLinks ||
		p.requireNoReferrer ||
		p.requireNoReferrerFullyQualifiedLinks ||
		p.addTargetBlankToFullyQualifiedLinks
}

func (p *Policy) addRelTargetBlank(t *token, href *url.URL) {
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
		noopener = p.setTargetBlank(t,
			external && p.addTargetBlankToFullyQualifiedLinks)
	}

	p.setRelAttr(t,
		p.requireNoFollow ||
			(external && p.requireNoFollowFullyQualifiedLinks),
		p.requireNoReferrer ||
			(external && p.requireNoReferrerFullyQualifiedLinks),
		noopener)
}

func externalLink(href *url.URL, t *token) (bool, bool) {
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

func (p *Policy) setTargetBlank(t *token, required bool) bool {
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

func (p *Policy) setRelAttr(t *token, nofollow, noreferrer, noopener bool) {
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

func (p *Policy) skipToken(t *token) bool {
	return len(t.Attr) == 0 && !p.allowNoAttrs(t.Data)
}

func (p *Policy) allowNoAttrs(elementName string) bool {
	if _, ok := p.setOfElementsAllowedWithoutAttrs[elementName]; ok {
		return true
	}

	for _, r := range p.setOfElementsMatchingAllowedWithoutAttrs {
		if r.MatchString(elementName) {
			return true
		}
	}
	return false
}

func (p *Policy) matchRegex(elementName string) (aps map[string][]attrPolicy) {
	for regex, attrs := range p.elsMatchingAndAttrs {
		if regex.MatchString(elementName) {
			if aps == nil {
				aps = make(map[string][]attrPolicy, len(attrs))
			}
			for k, v := range attrs {
				aps[k] = append(aps[k], v...)
			}
		}
	}
	return aps
}

func (p *Policy) sandboxIframe(t *token) {
	const sandbox = "sandbox"
	attr := t.Ref(sandbox)
	if attr == nil {
		t.Append(html.Attribute{Key: sandbox})
		return
	}

	values := slices.DeleteFunc(strings.Fields(attr.Val),
		func(s string) bool {
			_, ok := p.requireSandboxOnIFrame[s]
			return !ok
		})
	attr.Val = strings.Join(values, " ")
}
