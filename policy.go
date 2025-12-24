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
	relNoFollow bool

	// When true, add rel="nofollow" to HTML a, area, and link tags
	// Will add for href="http://foo"
	// Will skip for href="/foo" or href="foo"
	relNoFollowAbsOnly bool

	// When true, add rel="noreferrer" to HTML a, area, and link tags
	relNoReferrer bool

	// When true, add rel="noreferrer" to HTML a, area, and link tags
	// Will add for href="http://foo"
	// Will skip for href="/foo" or href="foo"
	relNoReferrerAbsOnly bool

	// When true, add crossorigin="anonymous" to HTML audio, img, link, script, and video tags
	crossoriginAnonymous bool

	// When true, add and filter sandbox attribute on iframe tags
	sandboxIframeAttrs map[string]struct{}

	// When true add target="_blank" to fully qualified links
	// Will add for href="http://foo"
	// Will skip for href="/foo" or href="foo"
	targetBlank bool

	// When true, URLs must be parseable by "net/url" url.Parse()
	parseableURLs bool

	// When true, u, _ := url.Parse("url"); !u.IsAbs() is permitted
	relativeURLs bool

	// When true, allow data attributes.
	dataAttributes bool

	// When true, allow comments.
	comments bool

	// map[htmlElementName]element
	elements map[string]*element

	// matchingElements stores regex based element matches along with attributes
	matchingElements map[*regexp.Regexp]*element

	// map[htmlAttributeName][]*attrPolicy
	globalAttrs map[string][]*attrPolicy

	// If urlPolicy is nil, all URLs with matching schema are allowed.
	// Otherwise, only the URLs with matching schema and urlPolicy(url)
	// returning true are allowed.
	urlSchemes map[string][]urlPolicy

	// These regexps are used to match allowed URL schemes, for example
	// if one would want to allow all URL schemes, they would add `.+`.
	// However pay attention as this can lead to XSS being rendered thus
	// defeating the purpose of using a HTML sanitizer.
	// The regexps are only considered if a schema was not explicitly
	// handled by `AllowURLSchemes` or `AllowURLSchemeWithCustomPolicy`.
	urlSchemeRegexps []*regexp.Regexp

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
	withoutAttrs map[string]struct{}

	// If an element has had all attributes removed as a result of a policy
	// being applied, then the element would be removed from the output.
	//
	// However some elements are valid and have strong layout meaning without
	// any attributes, i.e. <table>.
	//
	// In this case, any element matching a regular expression will be accepted without
	// attributes added.
	matchingWithoutAttrs []*regexp.Regexp

	skipContent map[string]struct{}

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
	unsafe bool

	// callbackAttr is callback function that will be called before element's
	// attributes are parsed. The callback function can add/remove/modify the
	// element's attributes. If the callback returns nil or empty array of html
	// attributes then the attributes will not be included in the output.
	callbackAttr func(*html.Token) []html.Attribute

	// If urlRewriter is not nil, it is used to rewrite any attribute of tags that
	// download resources, such as <a> or <img>. It requires that the URL is
	// parsable by "net/url" url.Parse().
	urlRewriter func(*html.Token, *url.URL) *url.URL

	setAttrs   map[string][]html.Attribute
	setAttrsIf map[string][]*setAttrPolicy

	styleHandler func(tag, style string) string

	open bool // pass all elements and attributes as is
}

type attrPolicy struct {
	single string
	values map[string]struct{}

	// optional pattern to match, when not nil the regexp needs to match
	// otherwise the attribute is removed
	regexp *regexp.Regexp
}

func (self *attrPolicy) Match(value string) bool {
	matched := true
	if self.single != "" {
		if strings.EqualFold(self.single, value) {
			return true
		}
		matched = false
	}

	if self.values != nil {
		if _, ok := self.values[strings.ToLower(value)]; ok {
			return true
		}
		matched = false
	}

	if self.regexp == nil {
		return matched
	}
	return self.regexp.MatchString(value)
}

type AttrPolicyBuilder struct {
	p *Policy

	attrNames  []string
	regexp     *regexp.Regexp
	values     []string
	allowEmpty bool
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
func (self *Policy) init() {
	if self.initialized {
		return
	}

	self.elements = map[string]*element{}
	self.matchingElements = map[*regexp.Regexp]*element{}
	self.globalAttrs = map[string][]*attrPolicy{}
	self.urlSchemes = map[string][]urlPolicy{}
	self.urlSchemeRegexps = []*regexp.Regexp{}
	self.withoutAttrs = map[string]struct{}{}
	self.skipContent = map[string]struct{}{}
	self.setAttrs = map[string][]html.Attribute{}
	self.setAttrsIf = map[string][]*setAttrPolicy{}
	self.initialized = true
}

// NewPolicy returns a blank policy with nothing allowed or permitted. This
// is the recommended way to start building a policy and you should now use
// AllowAttrs() and/or AllowElements() to construct the allowlist of HTML
// elements and attributes.
func NewPolicy() *Policy {
	p := &Policy{}
	p.addDefaultElementsWithoutAttrs()
	p.addDefaultSkipElementContent()
	return p
}

// SetCallbackForAttributes sets the callback function that will be called
// before element's attributes are parsed. The callback function can
// add/remove/modify the element's attributes. If the callback returns nil or
// empty array of html attributes then the attributes will not be included in
// the output. SetCallbackForAttributes is not goroutine safe.
func (self *Policy) SetCallbackForAttributes(
	cb func(*html.Token) []html.Attribute,
) *Policy {
	self.callbackAttr = cb
	return self
}

// RewriteTokenURL will rewrite any attribute of a resource downloading tag
// (e.g. <a>, <img>, <script>, <iframe>) using the provided function.
func (self *Policy) RewriteTokenURL(fn func(*html.Token, *url.URL) *url.URL,
) *Policy {
	self.urlRewriter = fn
	return self
}

// RewriteURL will rewrite any attribute of a resource downloading tag
// (e.g. <a>, <img>, <script>, <iframe>) using the provided function.
//
// Deprecated: Use RewriteTokenURL instead.
func (self *Policy) RewriteURL(fn func(*url.URL)) *Policy {
	return self.RewriteTokenURL(func(_ *html.Token, u *url.URL) *url.URL {
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
func (self *Policy) AllowAttrs(attrNames ...string) *AttrPolicyBuilder {
	self.init()

	abp := &AttrPolicyBuilder{
		p:         self,
		attrNames: make([]string, 0, len(attrNames)),
	}

	for _, attrName := range attrNames {
		abp.attrNames = append(abp.attrNames, strings.ToLower(attrName))
	}
	return abp
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
func (self *Policy) AllowDataAttributes() {
	self.dataAttributes = true
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
func (self *Policy) AllowComments() {
	self.comments = true
}

// AllowNoAttrs says that attributes on element are optional.
//
// The attribute policy is only added to the core policy when OnElements(...)
// are called.
func (self *Policy) AllowNoAttrs() *AttrPolicyBuilder {
	self.init()
	return &AttrPolicyBuilder{p: self, allowEmpty: true}
}

// AllowNoAttrs says that attributes on element are optional.
//
// The attribute policy is only added to the core policy when OnElements(...)
// are called.
func (self *AttrPolicyBuilder) AllowNoAttrs() *AttrPolicyBuilder {
	self.allowEmpty = true
	return self
}

// Matching allows a regular expression to be applied to a nascent attribute
// policy, and returns the attribute policy.
func (self *AttrPolicyBuilder) Matching(regex *regexp.Regexp) *AttrPolicyBuilder {
	self.regexp = regex
	return self
}

// WithValues allows given values and returns the attribute policy.
func (self *AttrPolicyBuilder) WithValues(values ...string) *AttrPolicyBuilder {
	self.values = values
	return self
}

// OnElements will bind an attribute policy to a given range of HTML elements
// and return the updated policy
func (self *AttrPolicyBuilder) OnElements(names ...string) *Policy {
	ap := self.attrPolicy()
	for _, name := range names {
		name = strings.ToLower(name)
		for _, attr := range self.attrNames {
			self.p.appendElement(name, attr, ap)
		}
		if self.allowEmpty {
			self.p.allowElement(name)
			self.p.withoutAttrs[name] = struct{}{}
		}
	}
	return self.p
}

func (self *AttrPolicyBuilder) attrPolicy() *attrPolicy {
	ap := &attrPolicy{regexp: self.regexp}
	switch n := len(self.values); {
	case n == 1:
		ap.single = self.values[0]
	case n > 1:
		ap.values = make(map[string]struct{}, n)
		for _, v := range self.values {
			ap.values[strings.ToLower(v)] = struct{}{}
		}
	}
	return ap
}

// DeleteFromElements will unbind an attribute policy, previously binded to a
// given range of HTML elements by OnElements, and return the updated policy.
func (self *AttrPolicyBuilder) DeleteFromElements(names ...string) *Policy {
	for _, name := range names {
		name = strings.ToLower(name)
		self.p.deleteElementAttrs(name, self.attrNames...)
		if self.allowEmpty {
			delete(self.p.withoutAttrs, name)
		}
	}
	return self.p
}

// OnElementsMatching will bind an attribute policy to all elements matching a
// given regex and return the updated policy
func (self *AttrPolicyBuilder) OnElementsMatching(re *regexp.Regexp) *Policy {
	ap := self.attrPolicy()
	for _, attr := range self.attrNames {
		self.p.appendMatching(re, attr, ap)
	}
	if self.allowEmpty {
		self.p.allowMatching(re)
		self.p.matchingWithoutAttrs = append(self.p.matchingWithoutAttrs, re)
	}
	return self.p
}

// Globally will bind an attribute policy to all HTML elements and return the
// updated policy
func (self *AttrPolicyBuilder) Globally() *Policy {
	ap := self.attrPolicy()
	for _, attr := range self.attrNames {
		self.p.globalAttrs[attr] = append(self.p.globalAttrs[attr], ap)
	}
	return self.p
}

// DeleteFromGlobally will unbind an attribute policy, previously binded by
// Globally, and return the updated policy.
func (self *AttrPolicyBuilder) DeleteFromGlobally() *Policy {
	for _, attr := range self.attrNames {
		delete(self.p.globalAttrs, attr)
	}
	return self.p
}

// WithStyleHandler sets h as a custom sanitizer for inline styles and returns
// updated policy.
//
// The custom sanitizer returns sanitized content of given style attribute for
// given tag. Returned empty string means style attribute is not allowed on this
// tag.
func (self *Policy) WithStyleHandler(h func(tag, style string) string) *Policy {
	self.styleHandler = h
	return self
}

// AllowElements will append HTML elements to the allowlist without applying an
// attribute policy to those elements (the elements are permitted
// sans-attributes)
func (self *Policy) AllowElements(names ...string) *Policy {
	self.init()
	for _, name := range names {
		self.allowElement(strings.ToLower(name))
	}
	return self
}

// AllowElementsMatching will append HTML elements to the allowlist if they
// match a regexp.
func (self *Policy) AllowElementsMatching(re *regexp.Regexp) *Policy {
	self.init()
	self.allowMatching(re)
	return self
}

// AllowURLSchemesMatching will append URL schemes to the allowlist if they
// match a regexp.
func (self *Policy) AllowURLSchemesMatching(r *regexp.Regexp) *Policy {
	self.urlSchemeRegexps = append(self.urlSchemeRegexps, r)
	return self
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
func (self *Policy) RewriteSrc(fn func(*url.URL)) *Policy {
	self.srcRewriter = fn
	return self
}

// RequireNoFollowOnLinks will result in all a, area, link tags having a
// rel="nofollow"added to them if one does not already exist
//
// Note: This requires p.RequireParseableURLs(true) and will enable it.
func (self *Policy) RequireNoFollowOnLinks(require bool) *Policy {
	self.relNoFollow = require
	self.parseableURLs = true
	return self
}

// RequireNoFollowOnFullyQualifiedLinks will result in all a, area, and link
// tags that point to a non-local destination (i.e. starts with a protocol and
// has a host) having a rel="nofollow" added to them if one does not already
// exist
//
// Note: This requires p.RequireParseableURLs(true) and will enable it.
func (self *Policy) RequireNoFollowOnFullyQualifiedLinks(require bool) *Policy {
	self.relNoFollowAbsOnly = require
	self.parseableURLs = true
	return self
}

// RequireNoReferrerOnLinks will result in all a, area, and link tags having a
// rel="noreferrrer" added to them if one does not already exist
//
// Note: This requires p.RequireParseableURLs(true) and will enable it.
func (self *Policy) RequireNoReferrerOnLinks(require bool) *Policy {
	self.relNoReferrer = require
	self.parseableURLs = true
	return self
}

// RequireNoReferrerOnFullyQualifiedLinks will result in all a, area, and link
// tags that point to a non-local destination (i.e. starts with a protocol and
// has a host) having a rel="noreferrer" added to them if one does not already
// exist
//
// Note: This requires p.RequireParseableURLs(true) and will enable it.
func (self *Policy) RequireNoReferrerOnFullyQualifiedLinks(require bool) *Policy {
	self.relNoReferrerAbsOnly = require
	self.parseableURLs = true
	return self
}

// RequireCrossOriginAnonymous will result in all audio, img, link, script, and
// video tags having a crossorigin="anonymous" added to them if one does not
// already exist
func (self *Policy) RequireCrossOriginAnonymous(require bool) *Policy {
	self.crossoriginAnonymous = require
	return self
}

// AddTargetBlankToFullyQualifiedLinks will result in all a, area and link tags
// that point to a non-local destination (i.e. starts with a protocol and has a
// host) having a target="_blank" added to them if one does not already exist
//
// Note: This requires p.RequireParseableURLs(true) and will enable it.
func (self *Policy) AddTargetBlankToFullyQualifiedLinks(require bool) *Policy {
	self.targetBlank = require
	self.parseableURLs = true
	return self
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
func (self *Policy) RequireParseableURLs(require bool) *Policy {
	self.parseableURLs = require
	return self
}

// AllowRelativeURLs enables RequireParseableURLs and then permits URLs that
// are parseable, have no schema information and url.IsAbs() returns false
// This permits local URLs
func (self *Policy) AllowRelativeURLs(require bool) *Policy {
	self.RequireParseableURLs(true)
	self.relativeURLs = require
	return self
}

// AllowURLSchemes will append URL schemes to the allowlist
// Example: p.AllowURLSchemes("mailto", "http", "https")
func (self *Policy) AllowURLSchemes(schemes ...string) *Policy {
	self.init()
	self.RequireParseableURLs(true)

	for _, scheme := range schemes {
		// Allow all URLs with matching scheme.
		self.urlSchemes[strings.ToLower(scheme)] = nil
	}
	return self
}

// AllowURLSchemeWithCustomPolicy will append URL schemes with
// a custom URL policy to the allowlist.
// Only the URLs with matching schema and urlPolicy(url)
// returning true will be allowed.
func (self *Policy) AllowURLSchemeWithCustomPolicy(scheme string,
	urlPolicy func(url *url.URL) (allowUrl bool),
) *Policy {
	self.init()
	self.RequireParseableURLs(true)

	scheme = strings.ToLower(scheme)
	self.urlSchemes[scheme] = append(self.urlSchemes[scheme], urlPolicy)
	return self
}

// RequireSandboxOnIFrame will result in all iframe tags having a sandbox="" tag
// Any sandbox values not specified here will be filtered from the generated HTML
func (self *Policy) RequireSandboxOnIFrame(vals ...SandboxValue) {
	self.sandboxIframeAttrs = make(map[string]struct{}, len(vals))

	for _, val := range vals {
		switch val {
		case SandboxAllowDownloads:
			self.sandboxIframeAttrs["allow-downloads"] = struct{}{}

		case SandboxAllowDownloadsWithoutUserActivation:
			self.sandboxIframeAttrs["allow-downloads-without-user-activation"] = struct{}{}

		case SandboxAllowForms:
			self.sandboxIframeAttrs["allow-forms"] = struct{}{}

		case SandboxAllowModals:
			self.sandboxIframeAttrs["allow-modals"] = struct{}{}

		case SandboxAllowOrientationLock:
			self.sandboxIframeAttrs["allow-orientation-lock"] = struct{}{}

		case SandboxAllowPointerLock:
			self.sandboxIframeAttrs["allow-pointer-lock"] = struct{}{}

		case SandboxAllowPopups:
			self.sandboxIframeAttrs["allow-popups"] = struct{}{}

		case SandboxAllowPopupsToEscapeSandbox:
			self.sandboxIframeAttrs["allow-popups-to-escape-sandbox"] = struct{}{}

		case SandboxAllowPresentation:
			self.sandboxIframeAttrs["allow-presentation"] = struct{}{}

		case SandboxAllowSameOrigin:
			self.sandboxIframeAttrs["allow-same-origin"] = struct{}{}

		case SandboxAllowScripts:
			self.sandboxIframeAttrs["allow-scripts"] = struct{}{}

		case SandboxAllowStorageAccessByUserActivation:
			self.sandboxIframeAttrs["allow-storage-access-by-user-activation"] = struct{}{}

		case SandboxAllowTopNavigation:
			self.sandboxIframeAttrs["allow-top-navigation"] = struct{}{}

		case SandboxAllowTopNavigationByUserActivation:
			self.sandboxIframeAttrs["allow-top-navigation-by-user-activation"] = struct{}{}
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
func (self *Policy) AddSpaceWhenStrippingTag(allow bool) *Policy {
	self.addSpaces = allow
	return self
}

// SkipElementsContent adds the HTML elements whose tags is needed to be removed
// with its content, if whose tags are not allowed. For allowed tags only their
// content be removed.
func (self *Policy) SkipElementsContent(names ...string) *Policy {
	self.init()
	for _, element := range names {
		self.skipContent[strings.ToLower(element)] = struct{}{}
	}
	return self
}

// AllowElementsContent marks the HTML elements whose content should be
// retained after removing the tag.
func (self *Policy) AllowElementsContent(names ...string) *Policy {
	self.init()
	for _, element := range names {
		delete(self.skipContent, strings.ToLower(element))
	}
	return self
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
func (self *Policy) AllowUnsafe(allowUnsafe bool) *Policy {
	self.init()
	self.unsafe = allowUnsafe
	return self
}
