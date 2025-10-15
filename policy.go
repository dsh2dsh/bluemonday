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

// TODO sgutzwiller create map of styles to default handlers
// TODO sgutzwiller create handlers for various attributes
import (
	"net/url"
	"regexp"
	"strings"

	"golang.org/x/net/html"

	"github.com/dsh2dsh/bluemonday/css"
)

// Policy encapsulates the allowlist of HTML elements and attributes that will
// be applied to the sanitised HTML.
//
// You should use bluemonday.NewPolicy() to create a blank policy as the
// unexported fields contain maps that need to be initialized.
type Policy struct {
	// Declares whether the maps have been initialized, used as a cheap check to
	// ensure that those using Policy{} directly won't cause nil pointer
	// exceptions
	initialized bool

	// If true then we add spaces when stripping tags, specifically the closing
	// tag is replaced by a space character.
	addSpaces bool

	// When true, add rel="nofollow" to HTML a, area, and link tags
	requireNoFollow bool

	// When true, add rel="nofollow" to HTML a, area, and link tags
	// Will add for href="http://foo"
	// Will skip for href="/foo" or href="foo"
	requireNoFollowFullyQualifiedLinks bool

	// When true, add rel="noreferrer" to HTML a, area, and link tags
	requireNoReferrer bool

	// When true, add rel="noreferrer" to HTML a, area, and link tags
	// Will add for href="http://foo"
	// Will skip for href="/foo" or href="foo"
	requireNoReferrerFullyQualifiedLinks bool

	// When true, add crossorigin="anonymous" to HTML audio, img, link, script, and video tags
	requireCrossOriginAnonymous bool

	// When true, add and filter sandbox attribute on iframe tags
	requireSandboxOnIFrame map[string]struct{}

	// When true add target="_blank" to fully qualified links
	// Will add for href="http://foo"
	// Will skip for href="/foo" or href="foo"
	addTargetBlankToFullyQualifiedLinks bool

	// When true, URLs must be parseable by "net/url" url.Parse()
	requireParseableURLs bool

	// When true, u, _ := url.Parse("url"); !u.IsAbs() is permitted
	allowRelativeURLs bool

	// When true, allow data attributes.
	allowDataAttributes bool

	// When true, allow comments.
	allowComments bool

	// map[htmlElementName]map[htmlAttributeName][]attrPolicy
	elsAndAttrs map[string]map[string][]attrPolicy

	// elsMatchingAndAttrs stores regex based element matches along with attributes
	elsMatchingAndAttrs map[*regexp.Regexp]map[string][]attrPolicy

	// map[htmlAttributeName][]attrPolicy
	globalAttrs map[string][]attrPolicy

	// If urlPolicy is nil, all URLs with matching schema are allowed.
	// Otherwise, only the URLs with matching schema and urlPolicy(url)
	// returning true are allowed.
	allowURLSchemes map[string][]urlPolicy

	// These regexps are used to match allowed URL schemes, for example
	// if one would want to allow all URL schemes, they would add `.+`.
	// However pay attention as this can lead to XSS being rendered thus
	// defeating the purpose of using a HTML sanitizer.
	// The regexps are only considered if a schema was not explicitly
	// handled by `AllowURLSchemes` or `AllowURLSchemeWithCustomPolicy`.
	allowURLSchemeRegexps []*regexp.Regexp

	// If srcRewriter is not nil, it is used to rewrite the src attribute
	// of tags that download resources, such as <img> and <script>.
	// It requires that the URL is parsable by "net/url" url.Parse().
	srcRewriter func(*url.URL)

	// If an element has had all attributes removed as a result of a policy
	// being applied, then the element would be removed from the output.
	//
	// However some elements are valid and have strong layout meaning without
	// any attributes, i.e. <table>. To prevent those being removed we maintain
	// a list of elements that are allowed to have no attributes and that will
	// be maintained in the output HTML.
	setOfElementsAllowedWithoutAttrs map[string]struct{}

	// If an element has had all attributes removed as a result of a policy
	// being applied, then the element would be removed from the output.
	//
	// However some elements are valid and have strong layout meaning without
	// any attributes, i.e. <table>.
	//
	// In this case, any element matching a regular expression will be accepted without
	// attributes added.
	setOfElementsMatchingAllowedWithoutAttrs []*regexp.Regexp

	setOfElementsToSkipContent map[string]struct{}

	// Permits fundamentally unsafe elements.
	//
	// If false (default) then elements such as `style` and `script` will not be
	// permitted even if declared in a policy. These elements when combined with
	// untrusted input cannot be safely handled by bluemonday at this point in
	// time.
	//
	// If true then `style` and `script` would be permitted by bluemonday if a
	// policy declares them. However this is not recommended under any circumstance
	// and can lead to XSS being rendered thus defeating the purpose of using a
	// HTML sanitizer.
	allowUnsafe bool

	// callbackAttr is callback function that will be called before element's
	// attributes are parsed. The callback function can add/remove/modify the
	// element's attributes. If the callback returns nil or empty array of html
	// attributes then the attributes will not be included in the output.
	callbackAttr func(*html.Token) []html.Attribute

	// If urlRewriter is not nil, it is used to rewrite any attribute of tags that
	// download resources, such as <a> or <img>. It requires that the URL is
	// parsable by "net/url" url.Parse().
	urlRewriter func(*html.Token, *url.URL) *url.URL

	setAttrs     map[string][]html.Attribute
	stylePolicy  *css.Policy
	styleHandler func(tag, style string) string
}

type attrPolicy struct {
	singleValue string
	values      map[string]struct{}

	// optional pattern to match, when not nil the regexp needs to match
	// otherwise the attribute is removed
	regexp *regexp.Regexp
}

func (self *attrPolicy) Match(value string) bool {
	matched := true
	if self.singleValue != "" {
		matched = false
		if strings.ToLower(value) == self.singleValue {
			return true
		}
	}

	if self.values != nil {
		matched = false
		v := strings.ToLower(value)
		if _, ok := self.values[v]; ok {
			return true
		}
	}

	if self.regexp != nil {
		matched = false
		if self.regexp.MatchString(value) {
			return true
		}
	}
	return matched
}

type AttrPolicyBuilder struct {
	p *Policy

	attrNames  []string
	regexp     *regexp.Regexp
	values     []string
	allowEmpty bool
}

type StylePolicyBuilder struct {
	p             *Policy
	policyBuilder *css.PolicyBuilder
}

type Attribute struct {
	p    *Policy
	attr html.Attribute
}

type urlPolicy func(url *url.URL) (allowUrl bool)

type SandboxValue int

const (
	SandboxAllowDownloads SandboxValue = iota
	SandboxAllowDownloadsWithoutUserActivation
	SandboxAllowForms
	SandboxAllowModals
	SandboxAllowOrientationLock
	SandboxAllowPointerLock
	SandboxAllowPopups
	SandboxAllowPopupsToEscapeSandbox
	SandboxAllowPresentation
	SandboxAllowSameOrigin
	SandboxAllowScripts
	SandboxAllowStorageAccessByUserActivation
	SandboxAllowTopNavigation
	SandboxAllowTopNavigationByUserActivation
)

// init initializes the maps if this has not been done already
func (p *Policy) init() {
	if p.initialized {
		return
	}

	p.elsAndAttrs = make(map[string]map[string][]attrPolicy)
	p.elsMatchingAndAttrs = make(map[*regexp.Regexp]map[string][]attrPolicy)
	p.globalAttrs = make(map[string][]attrPolicy)
	p.allowURLSchemes = make(map[string][]urlPolicy)
	p.allowURLSchemeRegexps = make([]*regexp.Regexp, 0)
	p.setOfElementsAllowedWithoutAttrs = make(map[string]struct{})
	p.setOfElementsToSkipContent = make(map[string]struct{})
	p.setAttrs = make(map[string][]html.Attribute)
	p.initialized = true
}

// NewPolicy returns a blank policy with nothing allowed or permitted. This
// is the recommended way to start building a policy and you should now use
// AllowAttrs() and/or AllowElements() to construct the allowlist of HTML
// elements and attributes.
func NewPolicy() *Policy {
	p := Policy{}

	p.addDefaultElementsWithoutAttrs()
	p.addDefaultSkipElementContent()

	return &p
}

// SetCallbackForAttributes sets the callback function that will be called
// before element's attributes are parsed. The callback function can
// add/remove/modify the element's attributes. If the callback returns nil or
// empty array of html attributes then the attributes will not be included in
// the output. SetCallbackForAttributes is not goroutine safe.
func (p *Policy) SetCallbackForAttributes(cb func(*html.Token) []html.Attribute,
) *Policy {
	p.callbackAttr = cb
	return p
}

// RewriteTokenURL will rewrite any attribute of a resource downloading tag
// (e.g. <a>, <img>, <script>, <iframe>) using the provided function.
func (p *Policy) RewriteTokenURL(fn func(*html.Token, *url.URL) *url.URL,
) *Policy {
	p.urlRewriter = fn
	return p
}

// RewriteURL will rewrite any attribute of a resource downloading tag
// (e.g. <a>, <img>, <script>, <iframe>) using the provided function.
//
// Deprecated: Use RewriteTokenURL instead.
func (p *Policy) RewriteURL(fn func(*url.URL)) *Policy {
	return p.RewriteTokenURL(func(_ *html.Token, u *url.URL) *url.URL {
		fn(u)
		var empty url.URL
		if *u == empty {
			return nil
		}
		return u
	})
}

// AllowAttrs takes a range of HTML attribute names and returns an
// attribute policy builder that allows you to specify the pattern and scope of
// the allowed attribute.
//
// The attribute policy is only added to the core policy when either Globally()
// or OnElements(...) are called.
func (p *Policy) AllowAttrs(attrNames ...string) *AttrPolicyBuilder {
	p.init()

	abp := AttrPolicyBuilder{
		p:          p,
		allowEmpty: false,
	}

	for _, attrName := range attrNames {
		abp.attrNames = append(abp.attrNames, strings.ToLower(attrName))
	}

	return &abp
}

// AllowDataAttributes permits all data attributes. We can't specify the name
// of each attribute exactly as they are customized.
//
// NOTE: These values are not sanitized and applications that evaluate or process
// them without checking and verification of the input may be at risk if this option
// is enabled. This is a 'caveat emptor' option and the person enabling this option
// needs to fully understand the potential impact with regards to whatever application
// will be consuming the sanitized HTML afterwards, i.e. if you know you put a link in a
// data attribute and use that to automatically load some new window then you're giving
// the author of a HTML fragment the means to open a malicious destination automatically.
// Use with care!
func (p *Policy) AllowDataAttributes() {
	p.allowDataAttributes = true
}

// AllowComments allows comments.
//
// Please note that only one type of comment will be allowed by this, this is the
// the standard HTML comment <!-- --> which includes the use of that to permit
// conditionals as per https://docs.microsoft.com/en-us/previous-versions/windows/internet-explorer/ie-developer/compatibility/ms537512(v=vs.85)?redirectedfrom=MSDN
//
// What is not permitted are CDATA XML comments, as the x/net/html package we depend
// on does not handle this fully and we are not choosing to take on that work:
// https://pkg.go.dev/golang.org/x/net/html#Tokenizer.AllowCDATA . If the x/net/html
// package changes this then these will be considered, otherwise if you AllowComments
// but provide a CDATA comment, then as per the documentation in x/net/html this will
// be treated as a plain HTML comment.
func (p *Policy) AllowComments() {
	p.allowComments = true
}

// AllowNoAttrs says that attributes on element are optional.
//
// The attribute policy is only added to the core policy when OnElements(...)
// are called.
func (p *Policy) AllowNoAttrs() *AttrPolicyBuilder {
	p.init()

	abp := AttrPolicyBuilder{
		p:          p,
		allowEmpty: true,
	}
	return &abp
}

// AllowNoAttrs says that attributes on element are optional.
//
// The attribute policy is only added to the core policy when OnElements(...)
// are called.
func (abp *AttrPolicyBuilder) AllowNoAttrs() *AttrPolicyBuilder {
	abp.allowEmpty = true
	return abp
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

// OnElements will set attribute on a given range of HTML elements and return
// the updated policy
func (self Attribute) OnElements(elements ...string) *Policy {
	if self.attr.Key == "" {
		return self.p
	}

	for _, element := range elements {
		element = strings.ToLower(element)
		self.p.setAttrs[element] = append(self.p.setAttrs[element], self.attr)
	}
	return self.p
}

// Matching allows a regular expression to be applied to a nascent attribute
// policy, and returns the attribute policy.
func (abp *AttrPolicyBuilder) Matching(regex *regexp.Regexp) *AttrPolicyBuilder {
	abp.regexp = regex
	return abp
}

// WithValues allows given values and returns the attribute policy.
func (abp *AttrPolicyBuilder) WithValues(values ...string) *AttrPolicyBuilder {
	abp.values = values
	return abp
}

// OnElements will bind an attribute policy to a given range of HTML elements
// and return the updated policy
func (abp *AttrPolicyBuilder) OnElements(elements ...string) *Policy {
	for _, element := range elements {
		element = strings.ToLower(element)

		for _, attr := range abp.attrNames {
			if _, ok := abp.p.elsAndAttrs[element]; !ok {
				abp.p.elsAndAttrs[element] = make(map[string][]attrPolicy)
			}
			abp.p.elsAndAttrs[element][attr] = append(
				abp.p.elsAndAttrs[element][attr], abp.attrPolicy())
		}

		if abp.allowEmpty {
			abp.p.setOfElementsAllowedWithoutAttrs[element] = struct{}{}

			if _, ok := abp.p.elsAndAttrs[element]; !ok {
				abp.p.elsAndAttrs[element] = make(map[string][]attrPolicy)
			}
		}
	}

	return abp.p
}

func (abp *AttrPolicyBuilder) attrPolicy() attrPolicy {
	ap := attrPolicy{regexp: abp.regexp}
	if n := len(abp.values); n == 1 {
		ap.singleValue = abp.values[0]
	} else if n > 1 {
		ap.values = make(map[string]struct{}, n)
		for _, v := range abp.values {
			v = strings.ToLower(v)
			ap.values[v] = struct{}{}
		}
	}
	return ap
}

// DeleteFromElements will unbind an attribute policy, previously binded to a
// given range of HTML elements by OnElements, and return the updated policy.
func (abp *AttrPolicyBuilder) DeleteFromElements(elements ...string) *Policy {
	for _, element := range elements {
		element = strings.ToLower(element)
		if _, ok := abp.p.elsAndAttrs[element]; ok {
			for _, attr := range abp.attrNames {
				delete(abp.p.elsAndAttrs[element], attr)
			}
		}
		if abp.allowEmpty {
			delete(abp.p.setOfElementsAllowedWithoutAttrs, element)
		}
	}
	return abp.p
}

// OnElementsMatching will bind an attribute policy to all elements matching a given regex
// and return the updated policy
func (abp *AttrPolicyBuilder) OnElementsMatching(regex *regexp.Regexp) *Policy {
	for _, attr := range abp.attrNames {
		if _, ok := abp.p.elsMatchingAndAttrs[regex]; !ok {
			abp.p.elsMatchingAndAttrs[regex] = make(map[string][]attrPolicy)
		}
		abp.p.elsMatchingAndAttrs[regex][attr] = append(
			abp.p.elsMatchingAndAttrs[regex][attr], abp.attrPolicy())
	}

	if abp.allowEmpty {
		abp.p.setOfElementsMatchingAllowedWithoutAttrs = append(
			abp.p.setOfElementsMatchingAllowedWithoutAttrs, regex)
		if _, ok := abp.p.elsMatchingAndAttrs[regex]; !ok {
			abp.p.elsMatchingAndAttrs[regex] = make(map[string][]attrPolicy)
		}
	}
	return abp.p
}

// Globally will bind an attribute policy to all HTML elements and return the
// updated policy
func (abp *AttrPolicyBuilder) Globally() *Policy {
	for _, attr := range abp.attrNames {
		if _, ok := abp.p.globalAttrs[attr]; !ok {
			abp.p.globalAttrs[attr] = []attrPolicy{}
		}
		abp.p.globalAttrs[attr] = append(abp.p.globalAttrs[attr], abp.attrPolicy())
	}
	return abp.p
}

// DeleteFromGlobally will unbind an attribute policy, previously binded by
// Globally, and return the updated policy.
func (abp *AttrPolicyBuilder) DeleteFromGlobally() *Policy {
	for _, attr := range abp.attrNames {
		delete(abp.p.globalAttrs, attr)
	}
	return abp.p
}

// WithStyleHandler sets h as a custom sanitizer for inline styles and returns
// updated policy.
//
// The custom sanitizer returns sanitized content of given style attribute for
// given tag. Returned empty string means style attribute is not allowed on this
// tag.
func (p *Policy) WithStyleHandler(h func(tag, style string) string) *Policy {
	p.styleHandler = h
	return p
}

// AllowStyles takes a range of CSS property names and returns a
// style policy builder that allows you to specify the pattern and scope of
// the allowed property.
//
// The style policy is only added to the core policy when either Globally()
// or OnElements(...) are called.
func (p *Policy) AllowStyles(propertyNames ...string) StylePolicyBuilder {
	p.init()
	if p.stylePolicy == nil {
		p.stylePolicy = css.NewPolicy()
	}

	return StylePolicyBuilder{
		p:             p,
		policyBuilder: p.stylePolicy.AllowStyles(propertyNames...),
	}
}

// Matching allows a regular expression to be applied to a nascent style
// policy, and returns the style policy.
func (spb StylePolicyBuilder) Matching(regex *regexp.Regexp,
) StylePolicyBuilder {
	spb.policyBuilder.Matching(regex)
	return spb
}

// MatchingEnum allows a list of allowed values to be applied to a nascent style
// policy, and returns the style policy.
func (spb StylePolicyBuilder) MatchingEnum(enum ...string) StylePolicyBuilder {
	spb.policyBuilder.MatchingEnum(enum...)
	return spb
}

// MatchingHandler allows a handler to be applied to a nascent style
// policy, and returns the style policy.
func (spb StylePolicyBuilder) MatchingHandler(handler func(string) bool,
) StylePolicyBuilder {
	spb.policyBuilder.MatchingHandler(handler)
	return spb
}

// OnElements will bind a style policy to a given range of HTML elements
// and return the updated policy
func (spb StylePolicyBuilder) OnElements(elements ...string) *Policy {
	spb.policyBuilder.OnElements(elements...)
	return spb.p
}

// OnElementsMatching will bind a style policy to any HTML elements matching the pattern
// and return the updated policy
func (spb StylePolicyBuilder) OnElementsMatching(regex *regexp.Regexp) *Policy {
	spb.policyBuilder.OnElementsMatching(regex)
	return spb.p
}

// Globally will bind a style policy to all HTML elements and return the
// updated policy
func (spb StylePolicyBuilder) Globally() *Policy {
	spb.policyBuilder.Globally()
	return spb.p
}

// AllowElements will append HTML elements to the allowlist without applying an
// attribute policy to those elements (the elements are permitted
// sans-attributes)
func (p *Policy) AllowElements(names ...string) *Policy {
	p.init()

	for _, element := range names {
		element = strings.ToLower(element)

		if _, ok := p.elsAndAttrs[element]; !ok {
			p.elsAndAttrs[element] = make(map[string][]attrPolicy)
		}
	}

	return p
}

// AllowElementsMatching will append HTML elements to the allowlist if they
// match a regexp.
func (p *Policy) AllowElementsMatching(regex *regexp.Regexp) *Policy {
	p.init()
	if _, ok := p.elsMatchingAndAttrs[regex]; !ok {
		p.elsMatchingAndAttrs[regex] = make(map[string][]attrPolicy)
	}
	return p
}

// AllowURLSchemesMatching will append URL schemes to the allowlist if they
// match a regexp.
func (p *Policy) AllowURLSchemesMatching(r *regexp.Regexp) *Policy {
	p.allowURLSchemeRegexps = append(p.allowURLSchemeRegexps, r)
	return p
}

// RewriteSrc will rewrite the src attribute of a resource downloading tag
// (e.g. <img>, <script>, <iframe>) using the provided function.
//
// Typically the use case here is that if the content that we're sanitizing
// is untrusted then the content that is inlined is also untrusted.
// To prevent serving this content on the same domain as the content appears
// on it is good practise to proxy the content through an additional domain
// name as this will force the web client to consider the inline content as
// third party to the main content, thus providing browser isolation around
// the inline content.
//
// An example of this is a web mail provider like fastmail.com , when an
// email (user generated content) is displayed, the email text is shown on
// fastmail.com but the inline attachments and content are rendered from
// fastmailusercontent.com . This proxying of the external content on a
// domain that is different to the content domain forces the browser domain
// security model to kick in. Note that this only applies to differences
// below the suffix (as per the publix suffix list).
//
// This is a good practise to adopt as it prevents the content from being
// able to set cookies on the main domain and thus prevents the content on
// the main domain from being able to read those cookies.
func (p *Policy) RewriteSrc(fn func(*url.URL)) *Policy {
	p.srcRewriter = fn
	return p
}

// RequireNoFollowOnLinks will result in all a, area, link tags having a
// rel="nofollow"added to them if one does not already exist
//
// Note: This requires p.RequireParseableURLs(true) and will enable it.
func (p *Policy) RequireNoFollowOnLinks(require bool) *Policy {
	p.requireNoFollow = require
	p.requireParseableURLs = true

	return p
}

// RequireNoFollowOnFullyQualifiedLinks will result in all a, area, and link
// tags that point to a non-local destination (i.e. starts with a protocol and
// has a host) having a rel="nofollow" added to them if one does not already
// exist
//
// Note: This requires p.RequireParseableURLs(true) and will enable it.
func (p *Policy) RequireNoFollowOnFullyQualifiedLinks(require bool) *Policy {
	p.requireNoFollowFullyQualifiedLinks = require
	p.requireParseableURLs = true

	return p
}

// RequireNoReferrerOnLinks will result in all a, area, and link tags having a
// rel="noreferrrer" added to them if one does not already exist
//
// Note: This requires p.RequireParseableURLs(true) and will enable it.
func (p *Policy) RequireNoReferrerOnLinks(require bool) *Policy {
	p.requireNoReferrer = require
	p.requireParseableURLs = true

	return p
}

// RequireNoReferrerOnFullyQualifiedLinks will result in all a, area, and link
// tags that point to a non-local destination (i.e. starts with a protocol and
// has a host) having a rel="noreferrer" added to them if one does not already
// exist
//
// Note: This requires p.RequireParseableURLs(true) and will enable it.
func (p *Policy) RequireNoReferrerOnFullyQualifiedLinks(require bool) *Policy {
	p.requireNoReferrerFullyQualifiedLinks = require
	p.requireParseableURLs = true

	return p
}

// RequireCrossOriginAnonymous will result in all audio, img, link, script, and
// video tags having a crossorigin="anonymous" added to them if one does not
// already exist
func (p *Policy) RequireCrossOriginAnonymous(require bool) *Policy {
	p.requireCrossOriginAnonymous = require

	return p
}

// AddTargetBlankToFullyQualifiedLinks will result in all a, area and link tags
// that point to a non-local destination (i.e. starts with a protocol and has a
// host) having a target="_blank" added to them if one does not already exist
//
// Note: This requires p.RequireParseableURLs(true) and will enable it.
func (p *Policy) AddTargetBlankToFullyQualifiedLinks(require bool) *Policy {
	p.addTargetBlankToFullyQualifiedLinks = require
	p.requireParseableURLs = true

	return p
}

// RequireParseableURLs will result in all URLs requiring that they be parseable
// by "net/url" url.Parse()
// This applies to:
// - a.href
// - area.href
// - blockquote.cite
// - img.src
// - link.href
// - script.src
func (p *Policy) RequireParseableURLs(require bool) *Policy {
	p.requireParseableURLs = require

	return p
}

// AllowRelativeURLs enables RequireParseableURLs and then permits URLs that
// are parseable, have no schema information and url.IsAbs() returns false
// This permits local URLs
func (p *Policy) AllowRelativeURLs(require bool) *Policy {
	p.RequireParseableURLs(true)
	p.allowRelativeURLs = require

	return p
}

// AllowURLSchemes will append URL schemes to the allowlist
// Example: p.AllowURLSchemes("mailto", "http", "https")
func (p *Policy) AllowURLSchemes(schemes ...string) *Policy {
	p.init()

	p.RequireParseableURLs(true)

	for _, scheme := range schemes {
		scheme = strings.ToLower(scheme)

		// Allow all URLs with matching scheme.
		p.allowURLSchemes[scheme] = nil
	}

	return p
}

// AllowURLSchemeWithCustomPolicy will append URL schemes with
// a custom URL policy to the allowlist.
// Only the URLs with matching schema and urlPolicy(url)
// returning true will be allowed.
func (p *Policy) AllowURLSchemeWithCustomPolicy(
	scheme string,
	urlPolicy func(url *url.URL) (allowUrl bool),
) *Policy {
	p.init()

	p.RequireParseableURLs(true)

	scheme = strings.ToLower(scheme)

	p.allowURLSchemes[scheme] = append(p.allowURLSchemes[scheme], urlPolicy)

	return p
}

// RequireSandboxOnIFrame will result in all iframe tags having a sandbox="" tag
// Any sandbox values not specified here will be filtered from the generated HTML
func (p *Policy) RequireSandboxOnIFrame(vals ...SandboxValue) {
	p.requireSandboxOnIFrame = make(map[string]struct{})

	for _, val := range vals {
		switch val {
		case SandboxAllowDownloads:
			p.requireSandboxOnIFrame["allow-downloads"] = struct{}{}

		case SandboxAllowDownloadsWithoutUserActivation:
			p.requireSandboxOnIFrame["allow-downloads-without-user-activation"] = struct{}{}

		case SandboxAllowForms:
			p.requireSandboxOnIFrame["allow-forms"] = struct{}{}

		case SandboxAllowModals:
			p.requireSandboxOnIFrame["allow-modals"] = struct{}{}

		case SandboxAllowOrientationLock:
			p.requireSandboxOnIFrame["allow-orientation-lock"] = struct{}{}

		case SandboxAllowPointerLock:
			p.requireSandboxOnIFrame["allow-pointer-lock"] = struct{}{}

		case SandboxAllowPopups:
			p.requireSandboxOnIFrame["allow-popups"] = struct{}{}

		case SandboxAllowPopupsToEscapeSandbox:
			p.requireSandboxOnIFrame["allow-popups-to-escape-sandbox"] = struct{}{}

		case SandboxAllowPresentation:
			p.requireSandboxOnIFrame["allow-presentation"] = struct{}{}

		case SandboxAllowSameOrigin:
			p.requireSandboxOnIFrame["allow-same-origin"] = struct{}{}

		case SandboxAllowScripts:
			p.requireSandboxOnIFrame["allow-scripts"] = struct{}{}

		case SandboxAllowStorageAccessByUserActivation:
			p.requireSandboxOnIFrame["allow-storage-access-by-user-activation"] = struct{}{}

		case SandboxAllowTopNavigation:
			p.requireSandboxOnIFrame["allow-top-navigation"] = struct{}{}

		case SandboxAllowTopNavigationByUserActivation:
			p.requireSandboxOnIFrame["allow-top-navigation-by-user-activation"] = struct{}{}
		}
	}
}

// AddSpaceWhenStrippingTag states whether to add a single space " " when
// removing tags that are not allowed by the policy.
//
// This is useful if you expect to strip tags in dense markup and may lose the
// value of whitespace.
//
// For example: "<p>Hello</p><p>World</p>"" would be sanitized to "HelloWorld"
// with the default value of false, but you may wish to sanitize this to
// " Hello  World " by setting AddSpaceWhenStrippingTag to true as this would
// retain the intent of the text.
func (p *Policy) AddSpaceWhenStrippingTag(allow bool) *Policy {
	p.addSpaces = allow

	return p
}

// SkipElementsContent adds the HTML elements whose tags is needed to be removed
// with its content, if whose tags are not allowed. For allowed tags only their
// content be removed.
func (p *Policy) SkipElementsContent(names ...string) *Policy {
	p.init()

	for _, element := range names {
		element = strings.ToLower(element)

		if _, ok := p.setOfElementsToSkipContent[element]; !ok {
			p.setOfElementsToSkipContent[element] = struct{}{}
		}
	}

	return p
}

// AllowElementsContent marks the HTML elements whose content should be
// retained after removing the tag.
func (p *Policy) AllowElementsContent(names ...string) *Policy {
	p.init()

	for _, element := range names {
		delete(p.setOfElementsToSkipContent, strings.ToLower(element))
	}

	return p
}

// AllowUnsafe permits fundamentally unsafe elements.
//
// If false (default) then elements such as `style` and `script` will not be
// permitted even if declared in a policy. These elements when combined with
// untrusted input cannot be safely handled by bluemonday at this point in
// time.
//
// If true then `style` and `script` would be permitted by bluemonday if a
// policy declares them. However this is not recommended under any circumstance
// and can lead to XSS being rendered thus defeating the purpose of using a
// HTML sanitizer.
func (p *Policy) AllowUnsafe(allowUnsafe bool) *Policy {
	p.init()
	p.allowUnsafe = allowUnsafe
	return p
}

// addDefaultElementsWithoutAttrs adds the HTML elements that we know are valid
// without any attributes to an internal map.
// i.e. we know that <table> is valid, but <bdo> isn't valid as the "dir" attr
// is mandatory
func (p *Policy) addDefaultElementsWithoutAttrs() {
	p.init()

	p.setOfElementsAllowedWithoutAttrs["abbr"] = struct{}{}
	p.setOfElementsAllowedWithoutAttrs["acronym"] = struct{}{}
	p.setOfElementsAllowedWithoutAttrs["address"] = struct{}{}
	p.setOfElementsAllowedWithoutAttrs["article"] = struct{}{}
	p.setOfElementsAllowedWithoutAttrs["aside"] = struct{}{}
	p.setOfElementsAllowedWithoutAttrs["audio"] = struct{}{}
	p.setOfElementsAllowedWithoutAttrs["b"] = struct{}{}
	p.setOfElementsAllowedWithoutAttrs["bdi"] = struct{}{}
	p.setOfElementsAllowedWithoutAttrs["blockquote"] = struct{}{}
	p.setOfElementsAllowedWithoutAttrs["body"] = struct{}{}
	p.setOfElementsAllowedWithoutAttrs["br"] = struct{}{}
	p.setOfElementsAllowedWithoutAttrs["button"] = struct{}{}
	p.setOfElementsAllowedWithoutAttrs["canvas"] = struct{}{}
	p.setOfElementsAllowedWithoutAttrs["caption"] = struct{}{}
	p.setOfElementsAllowedWithoutAttrs["center"] = struct{}{}
	p.setOfElementsAllowedWithoutAttrs["cite"] = struct{}{}
	p.setOfElementsAllowedWithoutAttrs["code"] = struct{}{}
	p.setOfElementsAllowedWithoutAttrs["col"] = struct{}{}
	p.setOfElementsAllowedWithoutAttrs["colgroup"] = struct{}{}
	p.setOfElementsAllowedWithoutAttrs["datalist"] = struct{}{}
	p.setOfElementsAllowedWithoutAttrs["dd"] = struct{}{}
	p.setOfElementsAllowedWithoutAttrs["del"] = struct{}{}
	p.setOfElementsAllowedWithoutAttrs["details"] = struct{}{}
	p.setOfElementsAllowedWithoutAttrs["dfn"] = struct{}{}
	p.setOfElementsAllowedWithoutAttrs["div"] = struct{}{}
	p.setOfElementsAllowedWithoutAttrs["dl"] = struct{}{}
	p.setOfElementsAllowedWithoutAttrs["dt"] = struct{}{}
	p.setOfElementsAllowedWithoutAttrs["em"] = struct{}{}
	p.setOfElementsAllowedWithoutAttrs["fieldset"] = struct{}{}
	p.setOfElementsAllowedWithoutAttrs["figcaption"] = struct{}{}
	p.setOfElementsAllowedWithoutAttrs["figure"] = struct{}{}
	p.setOfElementsAllowedWithoutAttrs["footer"] = struct{}{}
	p.setOfElementsAllowedWithoutAttrs["h1"] = struct{}{}
	p.setOfElementsAllowedWithoutAttrs["h2"] = struct{}{}
	p.setOfElementsAllowedWithoutAttrs["h3"] = struct{}{}
	p.setOfElementsAllowedWithoutAttrs["h4"] = struct{}{}
	p.setOfElementsAllowedWithoutAttrs["h5"] = struct{}{}
	p.setOfElementsAllowedWithoutAttrs["h6"] = struct{}{}
	p.setOfElementsAllowedWithoutAttrs["head"] = struct{}{}
	p.setOfElementsAllowedWithoutAttrs["header"] = struct{}{}
	p.setOfElementsAllowedWithoutAttrs["hgroup"] = struct{}{}
	p.setOfElementsAllowedWithoutAttrs["hr"] = struct{}{}
	p.setOfElementsAllowedWithoutAttrs["html"] = struct{}{}
	p.setOfElementsAllowedWithoutAttrs["i"] = struct{}{}
	p.setOfElementsAllowedWithoutAttrs["ins"] = struct{}{}
	p.setOfElementsAllowedWithoutAttrs["kbd"] = struct{}{}
	p.setOfElementsAllowedWithoutAttrs["li"] = struct{}{}
	p.setOfElementsAllowedWithoutAttrs["mark"] = struct{}{}
	p.setOfElementsAllowedWithoutAttrs["marquee"] = struct{}{}
	p.setOfElementsAllowedWithoutAttrs["nav"] = struct{}{}
	p.setOfElementsAllowedWithoutAttrs["ol"] = struct{}{}
	p.setOfElementsAllowedWithoutAttrs["optgroup"] = struct{}{}
	p.setOfElementsAllowedWithoutAttrs["option"] = struct{}{}
	p.setOfElementsAllowedWithoutAttrs["p"] = struct{}{}
	p.setOfElementsAllowedWithoutAttrs["picture"] = struct{}{}
	p.setOfElementsAllowedWithoutAttrs["pre"] = struct{}{}
	p.setOfElementsAllowedWithoutAttrs["q"] = struct{}{}
	p.setOfElementsAllowedWithoutAttrs["rp"] = struct{}{}
	p.setOfElementsAllowedWithoutAttrs["rt"] = struct{}{}
	p.setOfElementsAllowedWithoutAttrs["ruby"] = struct{}{}
	p.setOfElementsAllowedWithoutAttrs["s"] = struct{}{}
	p.setOfElementsAllowedWithoutAttrs["samp"] = struct{}{}
	p.setOfElementsAllowedWithoutAttrs["script"] = struct{}{}
	p.setOfElementsAllowedWithoutAttrs["section"] = struct{}{}
	p.setOfElementsAllowedWithoutAttrs["select"] = struct{}{}
	p.setOfElementsAllowedWithoutAttrs["small"] = struct{}{}
	p.setOfElementsAllowedWithoutAttrs["span"] = struct{}{}
	p.setOfElementsAllowedWithoutAttrs["strike"] = struct{}{}
	p.setOfElementsAllowedWithoutAttrs["strong"] = struct{}{}
	p.setOfElementsAllowedWithoutAttrs["style"] = struct{}{}
	p.setOfElementsAllowedWithoutAttrs["sub"] = struct{}{}
	p.setOfElementsAllowedWithoutAttrs["summary"] = struct{}{}
	p.setOfElementsAllowedWithoutAttrs["sup"] = struct{}{}
	p.setOfElementsAllowedWithoutAttrs["svg"] = struct{}{}
	p.setOfElementsAllowedWithoutAttrs["table"] = struct{}{}
	p.setOfElementsAllowedWithoutAttrs["tbody"] = struct{}{}
	p.setOfElementsAllowedWithoutAttrs["td"] = struct{}{}
	p.setOfElementsAllowedWithoutAttrs["textarea"] = struct{}{}
	p.setOfElementsAllowedWithoutAttrs["tfoot"] = struct{}{}
	p.setOfElementsAllowedWithoutAttrs["th"] = struct{}{}
	p.setOfElementsAllowedWithoutAttrs["thead"] = struct{}{}
	p.setOfElementsAllowedWithoutAttrs["title"] = struct{}{}
	p.setOfElementsAllowedWithoutAttrs["time"] = struct{}{}
	p.setOfElementsAllowedWithoutAttrs["tr"] = struct{}{}
	p.setOfElementsAllowedWithoutAttrs["tt"] = struct{}{}
	p.setOfElementsAllowedWithoutAttrs["u"] = struct{}{}
	p.setOfElementsAllowedWithoutAttrs["ul"] = struct{}{}
	p.setOfElementsAllowedWithoutAttrs["var"] = struct{}{}
	p.setOfElementsAllowedWithoutAttrs["video"] = struct{}{}
	p.setOfElementsAllowedWithoutAttrs["wbr"] = struct{}{}
}

// addDefaultSkipElementContent adds the HTML elements that we should skip
// rendering the character content of, if the element itself is not allowed.
// This is all character data that the end user would not normally see.
// i.e. if we exclude a <script> tag then we shouldn't render the JavaScript or
// anything else until we encounter the closing </script> tag.
func (p *Policy) addDefaultSkipElementContent() {
	p.init()

	p.setOfElementsToSkipContent["frame"] = struct{}{}
	p.setOfElementsToSkipContent["frameset"] = struct{}{}
	p.setOfElementsToSkipContent["iframe"] = struct{}{}
	p.setOfElementsToSkipContent["noembed"] = struct{}{}
	p.setOfElementsToSkipContent["noframes"] = struct{}{}
	p.setOfElementsToSkipContent["noscript"] = struct{}{}
	p.setOfElementsToSkipContent["nostyle"] = struct{}{}
	p.setOfElementsToSkipContent["object"] = struct{}{}
	p.setOfElementsToSkipContent["script"] = struct{}{}
	p.setOfElementsToSkipContent["style"] = struct{}{}
	p.setOfElementsToSkipContent["title"] = struct{}{}
}
