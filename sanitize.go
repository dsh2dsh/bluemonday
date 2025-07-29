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

	tokenizer := html.NewTokenizer(r)
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

		token := tokenizer.Token()
		switch token.Type {
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
				if _, err := buff.WriteString(token.String()); err != nil {
					return fmt.Errorf(genericErrMsg, err)
				}
			}

		case html.StartTagToken:

			if hidden > 0 {
				hidden++
				continue
			} else if containsHidden(token.Attr) {
				hidden++
				skipElementContent = true
				if err := p.maybeAddSpaces(buff); err != nil {
					return err
				}
				continue
			}

			recentlyStartedToken = token.DataAtom
			switch token.DataAtom {
			case atom.Script, atom.Style:
				if !p.allowUnsafe {
					continue
				}
			}

			aps, ok := p.elsAndAttrs[token.Data]
			if !ok {
				aa := p.matchRegex(token.Data)
				if aa == nil {
					if _, ok := p.setOfElementsToSkipContent[token.Data]; ok {
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

			if len(token.Attr) != 0 {
				token.Attr = p.sanitizeAttrs(&token, aps)
			}

			if p.skipToken(&token) {
				skipClosingTag = append(skipClosingTag, token.Data)
				if err := p.maybeAddSpaces(buff); err != nil {
					return err
				}
				break
			}

			if skipElementContent {
				continue
			} else if _, err := buff.WriteString(token.String()); err != nil {
				return fmt.Errorf(genericErrMsg, err)
			}

			switch token.DataAtom {
			case atom.Script, atom.Style:
			default:
				if _, ok := p.setOfElementsToSkipContent[token.Data]; ok {
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

			if recentlyStartedToken == token.DataAtom {
				recentlyStartedToken = 0
			}

			switch token.DataAtom {
			case atom.Script, atom.Style:
				if !p.allowUnsafe {
					continue
				}
			}

			if len(skipClosingTag) != 0 && skipClosingTag[len(skipClosingTag)-1] == token.Data {
				skipClosingTag = skipClosingTag[:len(skipClosingTag)-1]
				if err := p.maybeAddSpaces(buff); err != nil {
					return err
				}
				break
			}

			if _, ok := p.elsAndAttrs[token.Data]; !ok {
				var match bool
				for regex := range p.elsMatchingAndAttrs {
					if regex.MatchString(token.Data) {
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

			switch token.DataAtom {
			case atom.Script, atom.Style:
			default:
				_, ok := p.setOfElementsToSkipContent[token.Data]
				if skipElementContent && ok {
					skipElementContent = false
				}
			}

			if !skipElementContent {
				if _, err := buff.WriteString(token.String()); err != nil {
					return fmt.Errorf(genericErrMsg, err)
				}
			}

		case html.SelfClosingTagToken:

			if hidden > 0 {
				continue
			}

			switch token.DataAtom {
			case atom.Script, atom.Style:
				if !p.allowUnsafe {
					continue
				}
			}

			aps, ok := p.elsAndAttrs[token.Data]
			if !ok {
				aa := p.matchRegex(token.Data)
				if aa == nil {
					if err := p.maybeAddSpaces(buff); err != nil {
						return err
					}
					break
				}
				aps = aa
			}

			if len(token.Attr) != 0 {
				token.Attr = p.sanitizeAttrs(&token, aps)
			}

			if p.skipToken(&token) {
				if err := p.maybeAddSpaces(buff); err != nil {
					return err
				}
				break
			}

			if !skipElementContent {
				if _, err := buff.WriteString(token.String()); err != nil {
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
					if _, err := buff.WriteString(token.Data); err != nil {
						return fmt.Errorf(genericErrMsg, err)
					}
				}
			default:
				// HTML escape the text
				if _, err := buff.WriteString(token.String()); err != nil {
					return fmt.Errorf(genericErrMsg, err)
				}
			}

		default:
			// A token that didn't exist in the html package when we wrote this
			return fmt.Errorf("bluemonday: unknown token: %v", token)
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
// of html.Attributes that match the policies
func (p *Policy) sanitizeAttrs(t *html.Token, aps map[string][]attrPolicy,
) []html.Attribute {
	attrs := p.modifyTokenAttr(t)

	if len(attrs) == 0 {
		return attrs
	}

	// Builds a new attribute slice based on the whether the attribute has been
	// allowed explicitly or globally.
	cleanAttrs := attrs[:0]

attrsLoop:
	for i := range attrs {
		attr := &attrs[i]
		if p.allowDataAttributes && dataAttribute(attr.Key) {
			// If we see a data attribute, let it through.
			cleanAttrs = append(cleanAttrs, *attr)
			continue attrsLoop
		}

		// Is this a "style" attribute, and if so, do we need to sanitize it?
		if attr.Key == "style" && p.hasStylePolicies(t.Data) {
			p.sanitizeStyles(attr, t.Data)
			if attr.Val != "" {
				cleanAttrs = append(cleanAttrs, *attr)
			}
			// We've sanitized away any and all styles; don't bother to
			// output the style attribute (even if it's allowed)
			continue attrsLoop
		}

		// Is there an element specific attribute policy that applies?
		if apl, ok := aps[attr.Key]; ok {
			for _, ap := range apl {
				if ap.Match(attr.Val) {
					cleanAttrs = append(cleanAttrs, *attr)
					continue attrsLoop
				}
			}
		}

		// Is there a global attribute policy that applies?
		if apl, ok := p.globalAttrs[attr.Key]; ok {
			for _, ap := range apl {
				if ap.Match(attr.Val) {
					cleanAttrs = append(cleanAttrs, *attr)
					continue attrsLoop
				}
			}
		}
	}

	if len(cleanAttrs) == 0 {
		// If nothing was allowed, let's get out of here
		return cleanAttrs
	}
	// cleanAttrs now contains the attributes that are permitted

	if linkable(t) {
		cleanAttrs = p.sanitizeLinkable(t, cleanAttrs)
	}

	switch t.DataAtom {
	case atom.Audio, atom.Img, atom.Link, atom.Script, atom.Video:
		if p.requireCrossOriginAnonymous && len(cleanAttrs) > 0 {
			cleanAttrs = setAttribute(cleanAttrs, "crossorigin", "anonymous")
		}
	case atom.Iframe:
		if len(p.requireSandboxOnIFrame) != 0 {
			cleanAttrs = p.sandboxIframe(cleanAttrs)
		}
	}
	return cleanAttrs
}

func (p *Policy) modifyTokenAttr(t *html.Token) []html.Attribute {
	attrs := t.Attr
	if p.callbackAttr != nil {
		attrs = p.callbackAttr(t)
	}
	return attrs
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

func linkable(t *html.Token) bool {
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

func (p *Policy) sanitizeLinkable(t *html.Token, attrs []html.Attribute,
) []html.Attribute {
	var href *url.URL
	if p.requireParseableURLs {
		if href, attrs = p.validateURLs(t, attrs); href == nil {
			return attrs
		}
	}

	if p.requireRelTargetBlank() {
		attrs = p.addRelTargetBlank(t, href, attrs)
	}
	return attrs
}

// validateURLs ensures URLs are parseable:
// - a.href
// - area.href
// - link.href
// - blockquote.cite
// - q.cite
// - img.src
// - script.src
func (p *Policy) validateURLs(t *html.Token, attrs []html.Attribute,
) (href *url.URL, _ []html.Attribute) {
	switch t.DataAtom {
	case atom.A, atom.Area, atom.Base, atom.Link:
		href, attrs = p.deleteInvalidURL("href", attrs)

	case atom.Blockquote, atom.Del, atom.Ins, atom.Q:
		_, attrs = p.deleteInvalidURL("cite", attrs)

	case atom.Audio, atom.Embed, atom.Iframe, atom.Script, atom.Track:
		_, attrs = p.deleteInvalidURL("src", attrs, p.rewriteSrc)

	case atom.Img, atom.Source:
		src, attrs2 := p.deleteInvalidURL("src", attrs, p.rewriteSrc)
		attrs2, srcSetOk := p.sanitizeSrcSet(attrs2)
		if src == nil && !srcSetOk {
			return nil, nil
		}
		attrs = attrs2

	case atom.Video:
		_, attrs = p.deleteInvalidURL("poster", attrs, p.rewriteSrc)
		_, attrs = p.deleteInvalidURL("src", attrs, p.rewriteSrc)
	}
	return href, attrs
}

func (p *Policy) deleteInvalidURL(name string, attrs []html.Attribute,
	rewriters ...func(*url.URL) *url.URL,
) (*url.URL, []html.Attribute) {
	i, attr := findAttribute(name, attrs)
	if attr == nil {
		return nil, attrs
	}

	u := p.validURL(attr.Val)
	if u == nil {
		return nil, slices.Delete(attrs, i, i+1)
	}

	for _, fn := range rewriters {
		if u = fn(u); u == nil {
			return nil, slices.Delete(attrs, i, i+1)
		}
	}

	attr.Val = u.String()
	return u, attrs
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

func (p *Policy) sanitizeSrcSet(attrs []html.Attribute) ([]html.Attribute, bool) {
	i, attr := findAttribute("srcset", attrs)
	if attr == nil {
		return attrs, false
	}

	images := p.parseSrcSetAttribute(attr.Val)
	if len(images) == 0 {
		return slices.Delete(attrs, i, i+1), false
	}

	var removed int
	for _, img := range images {
		if u := p.rewriteSrc(img.URL()); u == nil {
			removed++
			img.ImageURL = ""
		}
	}

	if removed == len(images) {
		return slices.Delete(attrs, i, i+1), false
	} else if removed > 0 {
		images = slices.DeleteFunc(images, func(img *imageCandidate) bool {
			return img.ImageURL == ""
		})
		if len(images) == 0 {
			return slices.Delete(attrs, i, i+1), false
		}
	}

	attr.Val = images.String()
	return attrs, true
}

func (p *Policy) requireRelTargetBlank() bool {
	return p.requireNoFollow ||
		p.requireNoFollowFullyQualifiedLinks ||
		p.requireNoReferrer ||
		p.requireNoReferrerFullyQualifiedLinks ||
		p.addTargetBlankToFullyQualifiedLinks
}

func (p *Policy) addRelTargetBlank(t *html.Token, href *url.URL,
	attrs []html.Attribute,
) []html.Attribute {
	externalLink, ok := externalLink(href, attrs)
	if !ok {
		return attrs
	}
	attrs = slices.Grow(attrs, 2)

	var noopener bool
	if t.DataAtom == atom.A {
		// target="_blank" has a security risk that allows the opened window/tab to
		// issue JavaScript calls against window.opener, which in effect allow the
		// destination of the link to control the source:
		// https://dev.to/ben/the-targetblank-vulnerability-by-example
		//
		// To mitigate this risk, we need to add a specific rel attribute if it is
		// not already present: rel="noopener".
		attrs, noopener = p.setTargetAttr(attrs,
			externalLink && p.addTargetBlankToFullyQualifiedLinks)
	}

	return p.setRelAttr(attrs,
		p.requireNoFollow ||
			(externalLink && p.requireNoFollowFullyQualifiedLinks),
		p.requireNoReferrer ||
			(externalLink && p.requireNoReferrerFullyQualifiedLinks),
		noopener)
}

func externalLink(href *url.URL, attrs []html.Attribute) (bool, bool) {
	if href == nil {
		_, attr := findAttribute("href", attrs)
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

func (p *Policy) setTargetAttr(attrs []html.Attribute, required bool,
) ([]html.Attribute, bool) {
	const target, blank = "target", "_blank"
	_, attr := findAttribute(target, attrs)
	if required {
		if attr != nil {
			attr.Val = blank
		} else {
			attrs = append(attrs, html.Attribute{Key: target, Val: blank})
		}
		return attrs, true
	}

	if attr == nil {
		return attrs, false
	}
	return attrs, attr.Val == blank
}

func (p *Policy) setRelAttr(attrs []html.Attribute, nofollow, noreferrer,
	noopener bool,
) []html.Attribute {
	if !nofollow && !noreferrer && !noopener {
		return attrs
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

	_, attr := findAttribute("rel", attrs)
	if attr == nil {
		return append(attrs, html.Attribute{Key: "rel", Val: value()})
	} else if attr.Val == "" {
		attr.Val = value()
		return attrs
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
		return attrs
	}

	attr.Val += " " + value()
	return attrs
}

func (p *Policy) skipToken(t *html.Token) bool {
	return len(t.Attr) == 0 && !p.allowNoAttrs(t.Data)
}

func (p *Policy) allowNoAttrs(elementName string) bool {
	_, ok := p.setOfElementsAllowedWithoutAttrs[elementName]
	if ok {
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

func (p *Policy) sandboxIframe(attrs []html.Attribute) []html.Attribute {
	_, sandbox := findAttribute("sandbox", attrs)
	if sandbox == nil {
		return append(attrs, html.Attribute{Key: "sandbox"})
	}

	values := slices.DeleteFunc(strings.Fields(sandbox.Val),
		func(s string) bool {
			return !p.requireSandboxOnIFrame[s]
		})
	sandbox.Val = strings.Join(values, " ")
	return attrs
}
