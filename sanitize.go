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
	"strconv"
	"strings"

	"golang.org/x/net/html"

	"github.com/aymerick/douceur/parser"
)

const genericErrMsg = "bluemonday: %w"

var (
	dataAttribute             = regexp.MustCompile("^data-.+")
	dataAttributeXMLPrefix    = regexp.MustCompile("^xml.+")
	dataAttributeInvalidChars = regexp.MustCompile("[A-Z;]+")
	cssUnicodeChar            = regexp.MustCompile(`\\[0-9a-f]{1,6} ?`)
	dataURIbase64Prefix       = regexp.MustCompile(`^data:[^,]*;base64,`)
)

// Sanitize takes a string that contains a HTML fragment or document and applies
// the given policy allowlist.
//
// It returns a HTML string that has been sanitized by the policy or an empty
// string if an error has occurred (most likely as a consequence of extremely
// malformed input)
func (p *Policy) Sanitize(s string) string {
	if strings.TrimSpace(s) == "" {
		return s
	}

	return p.sanitizeWithBuff(strings.NewReader(s)).String()
}

// SanitizeBytes takes a []byte that contains a HTML fragment or document and applies
// the given policy allowlist.
//
// It returns a []byte containing the HTML that has been sanitized by the policy
// or an empty []byte if an error has occurred (most likely as a consequence of
// extremely malformed input)
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

// SanitizeReaderToWriter takes an io.Reader that contains a HTML fragment or document
// and applies the given policy allowlist and writes to the provided writer returning
// an error if there is one.
func (p *Policy) SanitizeReaderToWriter(r io.Reader, w io.Writer) error {
	return p.sanitize(r, w)
}

// Performs the actual sanitization process.
func (p *Policy) sanitizeWithBuff(r io.Reader) *bytes.Buffer {
	var buff bytes.Buffer
	if err := p.sanitize(r, &buff); err != nil {
		return &bytes.Buffer{}
	}
	return &buff
}

type asStringWriter struct {
	io.Writer
}

var _ io.StringWriter = (*asStringWriter)(nil)

func (a *asStringWriter) WriteString(s string) (int, error) {
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
		buff = &asStringWriter{w}
	}

	var (
		hidden                   int64
		skipElementContent       bool
		skipClosingTag           []string
		mostRecentlyStartedToken string
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

			mostRecentlyStartedToken = token.Data
			switch mostRecentlyStartedToken {
			case "script", "style":
				if !p.allowUnsafe {
					continue
				}
			}

			aps, ok := p.elsAndAttrs[token.Data]
			if !ok {
				aa, matched := p.matchRegex(token.Data)
				if !matched {
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
				token.Attr = p.sanitizeAttrs(token.Data, token.Attr, aps)
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

			switch mostRecentlyStartedToken {
			case "script", "style":
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

			elementName := token.Data
			if mostRecentlyStartedToken == elementName {
				mostRecentlyStartedToken = ""
			}

			if (elementName == "script" || elementName == "style") && !p.allowUnsafe {
				continue
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

			switch elementName {
			case "script", "style":
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

			switch token.Data {
			case "script", "style":
				if !p.allowUnsafe {
					continue
				}
			}

			aps, ok := p.elsAndAttrs[token.Data]
			if !ok {
				aa, matched := p.matchRegex(token.Data)
				if !matched {
					if err := p.maybeAddSpaces(buff); err != nil {
						return err
					}
					break
				}
				aps = aa
			}

			if len(token.Attr) != 0 {
				token.Attr = p.sanitizeAttrs(token.Data, token.Attr, aps)
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

			switch mostRecentlyStartedToken {
			case "script", "style":
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
func (p *Policy) sanitizeAttrs(elementName string, attrs []html.Attribute,
	aps map[string][]attrPolicy,
) []html.Attribute {
	if p.callbackAttr != nil {
		attrs = p.callbackAttr(elementName, attrs)
	}

	if len(attrs) == 0 {
		return attrs
	}

	hasStylePolicies := false
	sps, elementHasStylePolicies := p.elsAndStyles[elementName]
	if len(p.globalStyles) > 0 || (elementHasStylePolicies && len(sps) > 0) {
		hasStylePolicies = true
	}
	// no specific element policy found, look for a pattern match
	if !hasStylePolicies {
		for k, v := range p.elsMatchingAndStyles {
			if k.MatchString(elementName) {
				if len(v) > 0 {
					hasStylePolicies = true
					break
				}
			}
		}
	}

	// Builds a new attribute slice based on the whether the attribute has been
	// allowed explicitly or globally.
	cleanAttrs := attrs[:0]
attrsLoop:
	for _, htmlAttr := range attrs {
		if p.allowDataAttributes {
			// If we see a data attribute, let it through.
			if isDataAttribute(htmlAttr.Key) {
				cleanAttrs = append(cleanAttrs, htmlAttr)
				continue
			}
		}
		// Is this a "style" attribute, and if so, do we need to sanitize it?
		if htmlAttr.Key == "style" && hasStylePolicies {
			htmlAttr = p.sanitizeStyles(htmlAttr, elementName)
			if htmlAttr.Val == "" {
				// We've sanitized away any and all styles; don't bother to
				// output the style attribute (even if it's allowed)
				continue
			} else {
				cleanAttrs = append(cleanAttrs, htmlAttr)
				continue
			}
		}

		// Is there an element specific attribute policy that applies?
		if apl, ok := aps[htmlAttr.Key]; ok {
			for _, ap := range apl {
				if ap.Match(htmlAttr.Val) {
					cleanAttrs = append(cleanAttrs, htmlAttr)
					continue attrsLoop
				}
			}
		}

		// Is there a global attribute policy that applies?
		if apl, ok := p.globalAttrs[htmlAttr.Key]; ok {
			for _, ap := range apl {
				if ap.Match(htmlAttr.Val) {
					cleanAttrs = append(cleanAttrs, htmlAttr)
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

	if linkable(elementName) {
		if p.requireParseableURLs {
			// Ensure URLs are parseable:
			// - a.href
			// - area.href
			// - link.href
			// - blockquote.cite
			// - q.cite
			// - img.src
			// - script.src
			tmpAttrs := cleanAttrs[:0]
			for _, htmlAttr := range cleanAttrs {
				switch elementName {
				case "a", "area", "base", "link":
					if htmlAttr.Key == "href" {
						if u, ok := p.validURL(htmlAttr.Val); ok {
							htmlAttr.Val = u
							tmpAttrs = append(tmpAttrs, htmlAttr)
						}
						break
					}
					tmpAttrs = append(tmpAttrs, htmlAttr)
				case "blockquote", "del", "ins", "q":
					if htmlAttr.Key == "cite" {
						if u, ok := p.validURL(htmlAttr.Val); ok {
							htmlAttr.Val = u
							tmpAttrs = append(tmpAttrs, htmlAttr)
						}
						break
					}
					tmpAttrs = append(tmpAttrs, htmlAttr)
				case "audio", "embed", "iframe", "img", "script", "source", "track", "video":
					switch htmlAttr.Key {
					case "src":
						u, ok := p.validURL(htmlAttr.Val)
						if !ok {
							continue
						} else if u = p.rewriteSrc(u); u == "" {
							continue
						}
						htmlAttr.Val = u
					case "poster":
						u, ok := p.validURL(htmlAttr.Val)
						if !ok {
							continue
						}
						htmlAttr.Val = u
					}
					tmpAttrs = append(tmpAttrs, htmlAttr)
				default:
					tmpAttrs = append(tmpAttrs, htmlAttr)
				}
			}
			cleanAttrs = tmpAttrs
		}

		if (p.requireNoFollow ||
			p.requireNoFollowFullyQualifiedLinks ||
			p.requireNoReferrer ||
			p.requireNoReferrerFullyQualifiedLinks ||
			p.addTargetBlankToFullyQualifiedLinks) &&
			len(cleanAttrs) > 0 {

			// Add rel="nofollow" if a "href" exists
			switch elementName {
			case "a", "area", "base", "link":
				var hrefFound bool
				var externalLink bool
				for _, htmlAttr := range cleanAttrs {
					if htmlAttr.Key == "href" {
						hrefFound = true

						u, err := url.Parse(htmlAttr.Val)
						if err != nil {
							continue
						}
						if u.IsAbs() || u.Hostname() != "" {
							externalLink = true
						}

						continue
					}
				}

				if hrefFound {
					var (
						noFollowFound    bool
						noReferrerFound  bool
						targetBlankFound bool
					)

					addNoFollow := (p.requireNoFollow ||
						externalLink && p.requireNoFollowFullyQualifiedLinks)

					addNoReferrer := (p.requireNoReferrer ||
						externalLink && p.requireNoReferrerFullyQualifiedLinks)

					addTargetBlank := (externalLink &&
						p.addTargetBlankToFullyQualifiedLinks)

					tmpAttrs := cleanAttrs[:0]
					for _, htmlAttr := range cleanAttrs {

						var appended bool
						if htmlAttr.Key == "rel" && (addNoFollow || addNoReferrer) {

							if addNoFollow && !strings.Contains(htmlAttr.Val, "nofollow") {
								htmlAttr.Val += " nofollow"
							}
							if addNoReferrer && !strings.Contains(htmlAttr.Val, "noreferrer") {
								htmlAttr.Val += " noreferrer"
							}
							noFollowFound = addNoFollow
							noReferrerFound = addNoReferrer
							tmpAttrs = append(tmpAttrs, htmlAttr)
							appended = true
						}

						if elementName == "a" && htmlAttr.Key == "target" {
							if htmlAttr.Val == "_blank" {
								targetBlankFound = true
							}
							if addTargetBlank && !targetBlankFound {
								htmlAttr.Val = "_blank"
								targetBlankFound = true
								tmpAttrs = append(tmpAttrs, htmlAttr)
								appended = true
							}
						}

						if !appended {
							tmpAttrs = append(tmpAttrs, htmlAttr)
						}
					}
					if noFollowFound || noReferrerFound || targetBlankFound {
						cleanAttrs = tmpAttrs
					}

					if (addNoFollow && !noFollowFound) || (addNoReferrer && !noReferrerFound) {
						rel := html.Attribute{}
						rel.Key = "rel"
						if addNoFollow {
							rel.Val = "nofollow"
						}
						if addNoReferrer {
							if rel.Val != "" {
								rel.Val += " "
							}
							rel.Val += "noreferrer"
						}
						cleanAttrs = append(cleanAttrs, rel)
					}

					if elementName == "a" && addTargetBlank && !targetBlankFound {
						rel := html.Attribute{}
						rel.Key = "target"
						rel.Val = "_blank"
						targetBlankFound = true
						cleanAttrs = append(cleanAttrs, rel)
					}

					if targetBlankFound {
						// target="_blank" has a security risk that allows the
						// opened window/tab to issue JavaScript calls against
						// window.opener, which in effect allow the destination
						// of the link to control the source:
						// https://dev.to/ben/the-targetblank-vulnerability-by-example
						//
						// To mitigate this risk, we need to add a specific rel
						// attribute if it is not already present.
						// rel="noopener"
						//
						// Unfortunately this is processing the rel twice (we
						// already looked at it earlier ^^) as we cannot be sure
						// of the ordering of the href and rel, and whether we
						// have fully satisfied that we need to do this. This
						// double processing only happens *if* target="_blank"
						// is true.
						var noOpenerAdded bool
						tmpAttrs := cleanAttrs[:0]
						for _, htmlAttr := range cleanAttrs {
							var appended bool
							if htmlAttr.Key == "rel" {
								if strings.Contains(htmlAttr.Val, "noopener") {
									noOpenerAdded = true
									tmpAttrs = append(tmpAttrs, htmlAttr)
								} else {
									htmlAttr.Val += " noopener"
									noOpenerAdded = true
									tmpAttrs = append(tmpAttrs, htmlAttr)
								}

								appended = true
							}
							if !appended {
								tmpAttrs = append(tmpAttrs, htmlAttr)
							}
						}
						if noOpenerAdded {
							cleanAttrs = tmpAttrs
						} else {
							// rel attr was not found, or else noopener would
							// have been added already
							rel := html.Attribute{}
							rel.Key = "rel"
							rel.Val = "noopener"
							cleanAttrs = append(cleanAttrs, rel)
						}

					}
				}
			default:
			}
		}
	}

	if p.requireCrossOriginAnonymous && len(cleanAttrs) > 0 {
		switch elementName {
		case "audio", "img", "link", "script", "video":
			var crossOriginFound bool
			for i, htmlAttr := range cleanAttrs {
				if htmlAttr.Key == "crossorigin" {
					crossOriginFound = true
					cleanAttrs[i].Val = "anonymous"
				}
			}

			if !crossOriginFound {
				crossOrigin := html.Attribute{}
				crossOrigin.Key = "crossorigin"
				crossOrigin.Val = "anonymous"
				cleanAttrs = append(cleanAttrs, crossOrigin)
			}
		}
	}

	if p.requireSandboxOnIFrame != nil && elementName == "iframe" {
		var sandboxFound bool
		for i, htmlAttr := range cleanAttrs {
			if htmlAttr.Key == "sandbox" {
				sandboxFound = true
				var cleanVals []string
				cleanValsSet := make(map[string]bool)
				for val := range strings.FieldsSeq(htmlAttr.Val) {
					if p.requireSandboxOnIFrame[val] {
						if !cleanValsSet[val] {
							cleanVals = append(cleanVals, val)
							cleanValsSet[val] = true
						}
					}
				}
				cleanAttrs[i].Val = strings.Join(cleanVals, " ")
			}
		}

		if !sandboxFound {
			sandbox := html.Attribute{}
			sandbox.Key = "sandbox"
			sandbox.Val = ""
			cleanAttrs = append(cleanAttrs, sandbox)
		}
	}

	return cleanAttrs
}

func (p *Policy) sanitizeStyles(attr html.Attribute, elementName string) html.Attribute {
	sps := p.elsAndStyles[elementName]
	if len(sps) == 0 {
		sps = map[string][]stylePolicy{}
		// check for any matching elements, if we don't already have a policy found
		// if multiple matches are found they will be overwritten, it's best
		// to not have overlapping matchers
		for regex, policies := range p.elsMatchingAndStyles {
			if regex.MatchString(elementName) {
				for k, v := range policies {
					sps[k] = append(sps[k], v...)
				}
			}
		}
	}

	// Add semi-colon to end to fix parsing issue
	attr.Val = strings.TrimRight(attr.Val, " ")
	if len(attr.Val) > 0 && attr.Val[len(attr.Val)-1] != ';' {
		attr.Val += ";"
	}
	decs, err := parser.ParseDeclarations(attr.Val)
	if err != nil {
		attr.Val = ""
		return attr
	}
	clean := []string{}
	prefixes := []string{"-webkit-", "-moz-", "-ms-", "-o-", "mso-", "-xv-", "-atsc-", "-wap-", "-khtml-", "prince-", "-ah-", "-hp-", "-ro-", "-rim-", "-tc-"}

decLoop:
	for _, dec := range decs {
		tempProperty := strings.ToLower(dec.Property)
		tempValue := removeUnicode(strings.ToLower(dec.Value))
		for _, i := range prefixes {
			tempProperty = strings.TrimPrefix(tempProperty, i)
		}
		if spl, ok := sps[tempProperty]; ok {
			for _, sp := range spl {
				switch {
				case sp.handler != nil:
					if sp.handler(tempValue) {
						clean = append(clean, dec.Property+": "+dec.Value)
						continue decLoop
					}
				case len(sp.enum) > 0:
					if stringInSlice(tempValue, sp.enum) {
						clean = append(clean, dec.Property+": "+dec.Value)
						continue decLoop
					}
				case sp.regexp != nil:
					if sp.regexp.MatchString(tempValue) {
						clean = append(clean, dec.Property+": "+dec.Value)
						continue decLoop
					}
				}
			}
		}
		if spl, ok := p.globalStyles[tempProperty]; ok {
			for _, sp := range spl {
				switch {
				case sp.handler != nil:
					if sp.handler(tempValue) {
						clean = append(clean, dec.Property+": "+dec.Value)
						continue decLoop
					}
				case len(sp.enum) > 0:
					if stringInSlice(tempValue, sp.enum) {
						clean = append(clean, dec.Property+": "+dec.Value)
						continue decLoop
					}
				case sp.regexp != nil:
					if sp.regexp.MatchString(tempValue) {
						clean = append(clean, dec.Property+": "+dec.Value)
						continue decLoop
					}
				}
			}
		}
	}
	if len(clean) > 0 {
		attr.Val = strings.Join(clean, "; ")
	} else {
		attr.Val = ""
	}
	return attr
}

func (p *Policy) skipToken(t *html.Token) bool {
	return len(t.Attr) == 0 && !p.allowNoAttrs(t.Data)
}

func (p *Policy) allowNoAttrs(elementName string) bool {
	_, ok := p.setOfElementsAllowedWithoutAttrs[elementName]
	if !ok {
		for _, r := range p.setOfElementsMatchingAllowedWithoutAttrs {
			if r.MatchString(elementName) {
				ok = true
				break
			}
		}
	}
	return ok
}

func (p *Policy) validURL(rawurl string) (string, bool) {
	if !p.requireParseableURLs {
		return rawurl, true
	}

	// URLs are valid if when space is trimmed the URL is valid
	rawurl = strings.TrimSpace(rawurl)

	// URLs cannot contain whitespace, unless it is a data-uri
	if strings.Contains(rawurl, " ") ||
		strings.Contains(rawurl, "\t") ||
		strings.Contains(rawurl, "\n") {
		if !strings.HasPrefix(rawurl, `data:`) {
			return "", false
		}

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
		return "", false
	}

	if !u.IsAbs() {
		if p.allowRelativeURLs && u.String() != "" {
			return p.rewriteURL(u)
		}
		return "", false
	}

	urlPolicies, ok := p.allowURLSchemes[u.Scheme]
	if !ok {
		for _, r := range p.allowURLSchemeRegexps {
			if r.MatchString(u.Scheme) {
				return p.rewriteURL(u)
			}
		}
		return "", false
	}

	if len(urlPolicies) == 0 {
		return p.rewriteURL(u)
	}

	for _, urlPolicy := range urlPolicies {
		if urlPolicy(u) {
			return p.rewriteURL(u)
		}
	}
	return "", false
}

func (p *Policy) rewriteURL(u *url.URL) (string, bool) {
	if p.urlRewriter != nil {
		p.urlRewriter(u)
	}

	var empty url.URL
	if *u == empty {
		return "", false
	}
	return u.String(), true
}

func (p *Policy) rewriteSrc(src string) string {
	if p.srcRewriter == nil {
		return src
	}

	u, err := url.Parse(src)
	if err != nil {
		fmt.Println(err)
	}

	p.srcRewriter(u)
	return u.String()
}

func linkable(elementName string) bool {
	switch elementName {
	case "a", "area", "base", "link":
		// elements that allow .href
		return true
	case "blockquote", "del", "ins", "q":
		// elements that allow .cite
		return true
	case "audio", "embed", "iframe", "img", "input", "script", "source", "track", "video":
		// elements that allow .src
		return true
	default:
		return false
	}
}

// stringInSlice returns true if needle exists in haystack
func stringInSlice(needle string, haystack []string) bool {
	for _, straw := range haystack {
		if strings.EqualFold(straw, needle) {
			return true
		}
	}
	return false
}

func isDataAttribute(val string) bool {
	if !dataAttribute.MatchString(val) {
		return false
	}
	rest := strings.Split(val, "data-")
	if len(rest) == 1 {
		return false
	}
	// data-xml* is invalid.
	if dataAttributeXMLPrefix.MatchString(rest[1]) {
		return false
	}
	// no uppercase or semi-colons allowed.
	if dataAttributeInvalidChars.MatchString(rest[1]) {
		return false
	}
	return true
}

func removeUnicode(value string) string {
	substitutedValue := value
	currentLoc := cssUnicodeChar.FindStringIndex(substitutedValue)
	for currentLoc != nil {

		character := substitutedValue[currentLoc[0]+1 : currentLoc[1]]
		character = strings.TrimSpace(character)
		if len(character) < 4 {
			character = strings.Repeat("0", 4-len(character)) + character
		} else {
			for len(character) > 4 {
				if character[0] != '0' {
					character = ""
					break
				} else {
					character = character[1:]
				}
			}
		}
		character = "\\u" + character
		translatedChar, err := strconv.Unquote(`"` + character + `"`)
		translatedChar = strings.TrimSpace(translatedChar)
		if err != nil {
			return ""
		}
		substitutedValue = substitutedValue[0:currentLoc[0]] + translatedChar + substitutedValue[currentLoc[1]:]
		currentLoc = cssUnicodeChar.FindStringIndex(substitutedValue)
	}
	return substitutedValue
}

func (p *Policy) matchRegex(elementName string) (map[string][]attrPolicy, bool) {
	aps := make(map[string][]attrPolicy, 0)
	matched := false
	for regex, attrs := range p.elsMatchingAndAttrs {
		if regex.MatchString(elementName) {
			matched = true
			for k, v := range attrs {
				aps[k] = append(aps[k], v...)
			}
		}
	}
	return aps, matched
}
