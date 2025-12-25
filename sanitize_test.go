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
	_ "embed"
	"encoding/base64"
	"io"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/html"
	"golang.org/x/net/html/atom"
)

//go:embed testdata/miniflux_github.html
var githubHTML string

//go:embed testdata/miniflux_wikipedia.html
var wikipediaHTML string

func BenchmarkSanitize(b *testing.B) {
	inputs := []string{githubHTML, wikipediaHTML}

	p := UGCPolicy().
		AddTargetBlankToFullyQualifiedLinks(true).
		RequireNoReferrerOnLinks(true)

	var r strings.Reader

	b.ReportAllocs()
	for b.Loop() {
		for _, s := range inputs {
			r.Reset(s)
			p.SanitizeReaderToWriter(&r, io.Discard)
		}
	}
}

// test is a simple input vs output struct used to construct a slice of many
// tests to run within a single test method.
type test struct {
	in       string
	expected string
}

func TestEmpty(t *testing.T) {
	p := StrictPolicy()

	if p.Sanitize(``) != `` {
		t.Error("Empty string is not empty")
	}
}

func TestSignatureBehaviour(t *testing.T) {
	// https://github.com/microcosm-cc/bluemonday/issues/8
	p := UGCPolicy()

	input := "Hi.\n"

	if output := p.Sanitize(input); output != input {
		t.Errorf(`Sanitize() input = %s, output = %s`, input, output)
	}

	if output := string(p.SanitizeBytes([]byte(input))); output != input {
		t.Errorf(`SanitizeBytes() input = %s, output = %s`, input, output)
	}

	if output := p.SanitizeReader(
		strings.NewReader(input),
	).String(); output != input {
		t.Errorf(`SanitizeReader() input = %s, output = %s`, input, output)
	}

	input = "\t\n \n\t"

	if output := p.Sanitize(input); output != input {
		t.Errorf(`Sanitize() input = %s, output = %s`, input, output)
	}

	if output := string(p.SanitizeBytes([]byte(input))); output != input {
		t.Errorf(`SanitizeBytes() input = %s, output = %s`, input, output)
	}

	if output := p.SanitizeReader(
		strings.NewReader(input),
	).String(); output != input {
		t.Errorf(`SanitizeReader() input = %s, output = %s`, input, output)
	}
}

func TestLinks(t *testing.T) {
	tests := []test{
		{
			in:       `<a href="http://www.google.com">`,
			expected: `<a href="http://www.google.com" rel="nofollow">`,
		},
		{
			in:       `<a href="//www.google.com">`,
			expected: `<a href="//www.google.com" rel="nofollow">`,
		},
		{
			in:       `<a href="/www.google.com">`,
			expected: `<a href="/www.google.com" rel="nofollow">`,
		},
		{
			in:       `<a href="www.google.com">`,
			expected: `<a href="www.google.com" rel="nofollow">`,
		},
		{
			in:       `<a href="javascript:alert(1)">`,
			expected: ``,
		},
		{
			in:       `<a href="#">`,
			expected: ``,
		},
		{
			in:       `<a href="#top">`,
			expected: `<a href="#top" rel="nofollow">`,
		},
		{
			in:       `<a href="?q=1">`,
			expected: `<a href="?q=1" rel="nofollow">`,
		},
		{
			in:       `<a href="?q=1&r=2">`,
			expected: `<a href="?q=1&amp;r=2" rel="nofollow">`,
		},
		{
			in:       `<a href="?q=1&q=2">`,
			expected: `<a href="?q=1&amp;q=2" rel="nofollow">`,
		},
		{
			in:       `<a href="?q=%7B%22value%22%3A%22a%22%7D">`,
			expected: `<a href="?q=%7B%22value%22%3A%22a%22%7D" rel="nofollow">`,
		},
		{
			in:       `<a href="?q=1&r=2&s=:foo@">`,
			expected: `<a href="?q=1&amp;r=2&amp;s=:foo@" rel="nofollow">`,
		},
		{
			in: `<img src="data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAUAAAAFCAYAAACNbyblAAAAHElEQVQI12P4//8/w38GIAXDIBKE0DHxgljNBAAO9TXL0Y4OHwAAAABJRU5ErkJggg==" alt="Red dot" />`,
		},
		{
			in:       `<img src="giraffe.gif" />`,
			expected: `<img src="https://proxy.example.com/?u=giraffe.gif"/>`,
		},
		{
			in:       `<img src="giraffe.gif?height=500&amp;width=500&amp;flag" />`,
			expected: `<img src="https://proxy.example.com/?u=giraffe.gif?height=500&amp;width=500&amp;flag"/>`,
		},
		{
			in:       `<video src="giraffe.gif" />`,
			expected: `<video src="https://proxy.example.com/?u=giraffe.gif"/>`,
		},
		{
			in:       `<source src="giraffe.gif" />`,
			expected: `<source src="https://proxy.example.com/?u=giraffe.gif"/>`,
		},
	}

	p := UGCPolicy()
	p.RequireParseableURLs(true)
	p.AllowAttrs("src").OnElements("video", "source")
	p.RewriteSrc(func(u *url.URL) {
		// Proxify all requests to "https://proxy.example.com/?u=http://example.com/"
		// This is a contrived example, but it shows how to rewrite URLs
		// to proxy all requests through a single URL.

		url := u.String()
		u.Scheme = "https"
		u.Host = "proxy.example.com"
		u.Path = "/"
		u.RawQuery = "u=" + url
	})

	// These tests are run concurrently to enable the race detector to pick up
	// potential issues
	wg := sync.WaitGroup{}
	wg.Add(len(tests))
	for ii, tt := range tests {
		go func(ii int, tt test) {
			out := p.Sanitize(tt.in)
			if out != tt.expected {
				t.Errorf(
					"test %d failed;\ninput   : %s\noutput  : %s\nexpected: %s",
					ii,
					tt.in,
					out,
					tt.expected,
				)
			}
			wg.Done()
		}(ii, tt)
	}
	wg.Wait()
}

func TestLinkTargets(t *testing.T) {
	tests := []test{
		{
			in:       `<a href="http://www.google.com">`,
			expected: `<a href="http://www.google.com" target="_blank" rel="nofollow noopener">`,
		},
		{
			in:       `<a href="//www.google.com">`,
			expected: `<a href="//www.google.com" target="_blank" rel="nofollow noopener">`,
		},
		{
			in:       `<a href="/www.google.com">`,
			expected: `<a href="/www.google.com">`,
		},
		{
			in:       `<a href="www.google.com">`,
			expected: `<a href="www.google.com">`,
		},
		{
			in:       `<a href="javascript:alert(1)">`,
			expected: ``,
		},
		{
			in:       `<a href="#">`,
			expected: ``,
		},
		{
			in:       `<a href="#top">`,
			expected: `<a href="#top">`,
		},
		{
			in:       `<a href="?q=1">`,
			expected: `<a href="?q=1">`,
		},
		{
			in: `<img src="data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAUAAAAFCAYAAACNbyblAAAAHElEQVQI12P4//8/w38GIAXDIBKE0DHxgljNBAAO9TXL0Y4OHwAAAABJRU5ErkJggg==" alt="Red dot" />`,
		},
		{
			in:       `<img src="giraffe.gif" />`,
			expected: `<img src="giraffe.gif"/>`,
		},
	}

	p := UGCPolicy()
	p.RequireParseableURLs(true)
	p.RequireNoFollowOnLinks(false)
	p.RequireNoFollowOnFullyQualifiedLinks(true)
	p.AddTargetBlankToFullyQualifiedLinks(true)

	// These tests are run concurrently to enable the race detector to pick up
	// potential issues
	wg := sync.WaitGroup{}
	wg.Add(len(tests))
	for ii, tt := range tests {
		go func(ii int, tt test) {
			out := p.Sanitize(tt.in)
			if out != tt.expected {
				t.Errorf(
					"test %d failed;\ninput   : %s\noutput  : %s\nexpected: %s",
					ii,
					tt.in,
					out,
					tt.expected,
				)
			}
			wg.Done()
		}(ii, tt)
	}
	wg.Wait()
}

func TestStyling(t *testing.T) {
	tests := []test{
		{
			in:       `<span class="foo">Hello World</span>`,
			expected: `<span class="foo">Hello World</span>`,
		},
		{
			in:       `<span class="foo bar654">Hello World</span>`,
			expected: `<span class="foo bar654">Hello World</span>`,
		},
	}

	p := UGCPolicy()
	p.AllowStyling()

	// These tests are run concurrently to enable the race detector to pick up
	// potential issues
	wg := sync.WaitGroup{}
	wg.Add(len(tests))
	for ii, tt := range tests {
		go func(ii int, tt test) {
			out := p.Sanitize(tt.in)
			if out != tt.expected {
				t.Errorf(
					"test %d failed;\ninput   : %s\noutput  : %s\nexpected: %s",
					ii,
					tt.in,
					out,
					tt.expected,
				)
			}
			wg.Done()
		}(ii, tt)
	}
	wg.Wait()
}

func TestEmptyAttributes(t *testing.T) {
	p := UGCPolicy()
	// Do not do this, especially without a Matching() clause, this is a test
	p.AllowAttrs("disabled").OnElements("textarea")

	tests := []test{
		// Empty elements
		{
			in: `<textarea>text</textarea><textarea disabled></textarea>` +
				`<div onclick='redirect()'><span>Styled by span</span></div>`,
			expected: `<textarea>text</textarea><textarea disabled=""></textarea>` +
				`<div><span>Styled by span</span></div>`,
		},
		{
			in:       `foo<br />bar`,
			expected: `foo<br/>bar`,
		},
		{
			in:       `foo<br/>bar`,
			expected: `foo<br/>bar`,
		},
		{
			in:       `foo<br>bar`,
			expected: `foo<br>bar`,
		},
		{
			in:       `foo<hr noshade>bar`,
			expected: `foo<hr>bar`,
		},
	}

	for ii, test := range tests {
		out := p.Sanitize(test.in)
		if out != test.expected {
			t.Errorf(
				"test %d failed;\ninput   : %s\noutput  : %s\nexpected: %s",
				ii,
				test.in,
				out,
				test.expected,
			)
		}
	}
}

func TestDataAttributes(t *testing.T) {
	p := UGCPolicy()
	p.AllowDataAttributes()

	tests := []test{
		{
			in:       `<p data-cfg="dave">text</p>`,
			expected: `<p data-cfg="dave">text</p>`,
		},
		{
			in:       `<p data-component="dave">text</p>`,
			expected: `<p data-component="dave">text</p>`,
		},
		{
			in:       `<p data-semicolon;="dave">text</p>`,
			expected: `<p>text</p>`,
		},
		{
			in:       `<p data-xml-prefix="dave">text</p>`,
			expected: `<p>text</p>`,
		},
	}

	for ii, test := range tests {
		out := p.Sanitize(test.in)
		if out != test.expected {
			t.Errorf(
				"test %d failed;\ninput   : %s\noutput  : %s\nexpected: %s",
				ii,
				test.in,
				out,
				test.expected,
			)
		}
	}
}

func TestDataUri(t *testing.T) {
	p := UGCPolicy()
	p.AllowURLSchemeWithCustomPolicy(
		"data",
		func(url *url.URL) (allowUrl bool) {
			// Allows PNG images only
			const prefix = "image/png;base64,"
			if !strings.HasPrefix(url.Opaque, prefix) {
				return false
			}
			if _, err := base64.StdEncoding.DecodeString(url.Opaque[len(prefix):]); err != nil {
				return false
			}
			if url.RawQuery != "" || url.Fragment != "" {
				return false
			}
			return true
		},
	)

	tests := []test{
		{
			in:       `<img src="data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAUAAAAFCAYAAACNbyblAAAAHElEQVQI12P4//8/w38GIAXDIBKE0DHxgljNBAAO9TXL0Y4OHwAAAABJRU5ErkJggg==">`,
			expected: `<img src="data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAUAAAAFCAYAAACNbyblAAAAHElEQVQI12P4//8/w38GIAXDIBKE0DHxgljNBAAO9TXL0Y4OHwAAAABJRU5ErkJggg==">`,
		},
		{
			in:       `<img src="data:text/javascript;charset=utf-8,alert('hi');">`,
			expected: ``,
		},
		{
			in:       `<img src="data:image/png;base64,charset=utf-8,alert('hi');">`,
			expected: ``,
		},
		{
			in:       `<img src="data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAUAAAAFCAYAAACNbyblAAAAHElEQVQI12P4-_8/w38GIAXDIBKE0DHxgljNBAAO9TXL0Y4OHwAAAABJRU5ErkJggg==">`,
			expected: ``,
		},
	}

	for ii, test := range tests {
		out := p.Sanitize(test.in)
		if out != test.expected {
			t.Errorf(
				"test %d failed;\ninput   : %s\noutput  : %s\nexpected: %s",
				ii,
				test.in,
				out,
				test.expected,
			)
		}
	}
}

func TestGlobalURLPatternsViaCustomPolicy(t *testing.T) {
	p := UGCPolicy()
	// youtube embeds
	p.AllowElements("iframe")
	p.AllowAttrs("width", "height", "frameborder").Matching(Integer).OnElements("iframe")
	p.AllowAttrs("allow").Matching(regexp.MustCompile(`^(([\p{L}\p{N}_-]+)(; )?)+$`)).OnElements("iframe")
	p.AllowAttrs("allowfullscreen").OnElements("iframe")
	p.AllowAttrs("src").OnElements("iframe")
	// These clobber... so you only get one and it applies to URLs everywhere
	p.AllowURLSchemeWithCustomPolicy("mailto", func(url *url.URL) (allowUrl bool) { return false })
	p.AllowURLSchemeWithCustomPolicy("http", func(url *url.URL) (allowUrl bool) { return false })
	p.AllowURLSchemeWithCustomPolicy(
		"https",
		func(url *url.URL) bool {
			// Allow YouTube
			return url.Host == `www.youtube.com`
		},
	)

	tests := []test{
		{
			in:       `<iframe width="560" height="315" src="https://www.youtube.com/embed/lJIrF4YjHfQ" title="YouTube video player" frameborder="0" allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture" allowfullscreen></iframe>`,
			expected: `<iframe width="560" height="315" src="https://www.youtube.com/embed/lJIrF4YjHfQ" title="YouTube video player" frameborder="0" allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture" allowfullscreen=""></iframe>`,
		},
		{
			in: `<iframe width="560" height="315" src="htt://www.vimeo.com/embed/lJIrF4YjHfQ" title="YouTube video player" frameborder="0" allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture" allowfullscreen></iframe>`,
		},
	}

	for ii, test := range tests {
		out := p.Sanitize(test.in)
		if out != test.expected {
			t.Errorf(
				"test %d failed;\ninput   : %s\noutput  : %s\nexpected: %s",
				ii,
				test.in,
				out,
				test.expected,
			)
		}
	}
}

func TestELementURLPatternsMatching(t *testing.T) {
	p := UGCPolicy()
	// youtube embeds
	p.AllowElements("iframe")
	p.AllowAttrs("width", "height", "frameborder").Matching(Integer).OnElements("iframe")
	p.AllowAttrs("allow").Matching(regexp.MustCompile(`^(([\p{L}\p{N}_-]+)(; )?)+$`)).OnElements("iframe")
	p.AllowAttrs("allowfullscreen").OnElements("iframe")
	p.AllowAttrs("src").Matching(regexp.MustCompile(`^https://www.youtube.com/.*$`)).OnElements("iframe")

	tests := []test{
		{
			in:       `<iframe width="560" height="315" src="https://www.youtube.com/embed/lJIrF4YjHfQ" title="YouTube video player" frameborder="0" allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture" allowfullscreen></iframe>`,
			expected: `<iframe width="560" height="315" src="https://www.youtube.com/embed/lJIrF4YjHfQ" title="YouTube video player" frameborder="0" allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture" allowfullscreen=""></iframe>`,
		},
		{
			in: `<iframe width="560" height="315" src="htt://www.vimeo.com/embed/lJIrF4YjHfQ" title="YouTube video player" frameborder="0" allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture" allowfullscreen></iframe>`,
		},
	}

	for ii, test := range tests {
		out := p.Sanitize(test.in)
		if out != test.expected {
			t.Errorf(
				"test %d failed;\ninput   : %s\noutput  : %s\nexpected: %s",
				ii,
				test.in,
				out,
				test.expected,
			)
		}
	}
}

func TestAntiSamy(t *testing.T) {
	standardUrls := regexp.MustCompile(`(?i)^https?|mailto`)

	p := NewPolicy()

	p.AllowElements(
		"a", "b", "br", "div", "font", "i", "img", "input", "li", "ol", "p",
		"span", "td", "ul",
	)
	p.AllowAttrs("checked", "type").OnElements("input")
	p.AllowAttrs("color").OnElements("font")
	p.AllowAttrs("href").Matching(standardUrls).OnElements("a")
	p.AllowAttrs("src").Matching(standardUrls).OnElements("img")
	p.AllowAttrs("class", "id", "title").Globally()
	p.AllowAttrs("char").Matching(
		regexp.MustCompile(`p{L}`), // Single character or HTML entity only
	).OnElements("td")

	tests := []test{
		// Base64 strings
		//
		// first string is
		// <a - href="http://www.owasp.org">click here</a>
		{
			in:       `PGEgLSBocmVmPSJodHRwOi8vd3d3Lm93YXNwLm9yZyI+Y2xpY2sgaGVyZTwvYT4=`,
			expected: `PGEgLSBocmVmPSJodHRwOi8vd3d3Lm93YXNwLm9yZyI+Y2xpY2sgaGVyZTwvYT4=`,
		},
		// the rest are randomly generated 300 byte sequences which generate
		// parser errors, turned into Strings
		{
			in:       `uz0sEy5aDiok6oufQRaYPyYOxbtlACRnfrOnUVIbOstiaoB95iw+dJYuO5sI9nudhRtSYLANlcdgO0pRb+65qKDwZ5o6GJRMWv4YajZk+7Q3W/GN295XmyWUpxuyPGVi7d5fhmtYaYNW6vxyKK1Wjn9IEhIrfvNNjtEF90vlERnz3wde4WMaKMeciqgDXuZHEApYmUcu6Wbx4Q6WcNDqohAN/qCli74tvC+Umy0ZsQGU7E+BvJJ1tLfMcSzYiz7Q15ByZOYrA2aa0wDu0no3gSatjGt6aB4h30D9xUP31LuPGZ2GdWwMfZbFcfRgDSh42JPwa1bODmt5cw0Y8ACeyrIbfk9IkX1bPpYfIgtO7TwuXjBbhh2EEixOZ2YkcsvmcOSVTvraChbxv6kP`,
			expected: `uz0sEy5aDiok6oufQRaYPyYOxbtlACRnfrOnUVIbOstiaoB95iw+dJYuO5sI9nudhRtSYLANlcdgO0pRb+65qKDwZ5o6GJRMWv4YajZk+7Q3W/GN295XmyWUpxuyPGVi7d5fhmtYaYNW6vxyKK1Wjn9IEhIrfvNNjtEF90vlERnz3wde4WMaKMeciqgDXuZHEApYmUcu6Wbx4Q6WcNDqohAN/qCli74tvC+Umy0ZsQGU7E+BvJJ1tLfMcSzYiz7Q15ByZOYrA2aa0wDu0no3gSatjGt6aB4h30D9xUP31LuPGZ2GdWwMfZbFcfRgDSh42JPwa1bODmt5cw0Y8ACeyrIbfk9IkX1bPpYfIgtO7TwuXjBbhh2EEixOZ2YkcsvmcOSVTvraChbxv6kP`,
		},
		{
			in:       `PIWjMV4y+MpuNLtcY3vBRG4ZcNaCkB9wXJr3pghmFA6rVXAik+d5lei48TtnHvfvb5rQZVceWKv9cR/9IIsLokMyN0omkd8j3TV0DOh3JyBjPHFCu1Gp4Weo96h5C6RBoB0xsE4QdS2Y1sq/yiha9IebyHThAfnGU8AMC4AvZ7DDBccD2leZy2Q617ekz5grvxEG6tEcZ3fCbJn4leQVVo9MNoerim8KFHGloT+LxdgQR6YN5y1ii3bVGreM51S4TeANujdqJXp8B7B1Gk3PKCRS2T1SNFZedut45y+/w7wp5AUQCBUpIPUj6RLp+y3byWhcbZbJ70KOzTSZuYYIKLLo8047Fej43bIaghJm0F9yIKk3C5gtBcw8T5pciJoVXrTdBAK/8fMVo29P`,
			expected: `PIWjMV4y+MpuNLtcY3vBRG4ZcNaCkB9wXJr3pghmFA6rVXAik+d5lei48TtnHvfvb5rQZVceWKv9cR/9IIsLokMyN0omkd8j3TV0DOh3JyBjPHFCu1Gp4Weo96h5C6RBoB0xsE4QdS2Y1sq/yiha9IebyHThAfnGU8AMC4AvZ7DDBccD2leZy2Q617ekz5grvxEG6tEcZ3fCbJn4leQVVo9MNoerim8KFHGloT+LxdgQR6YN5y1ii3bVGreM51S4TeANujdqJXp8B7B1Gk3PKCRS2T1SNFZedut45y+/w7wp5AUQCBUpIPUj6RLp+y3byWhcbZbJ70KOzTSZuYYIKLLo8047Fej43bIaghJm0F9yIKk3C5gtBcw8T5pciJoVXrTdBAK/8fMVo29P`,
		},
		{
			in:       `uCk7HocubT6KzJw2eXpSUItZFGkr7U+D89mJw70rxdqXP2JaG04SNjx3dd84G4bz+UVPPhPO2gBAx2vHI0xhgJG9T4vffAYh2D1kenmr+8gIHt6WDNeD+HwJeAbJYhfVFMJsTuIGlYIw8+I+TARK0vqjACyRwMDAndhXnDrk4E5U3hyjqS14XX0kIDZYM6FGFPXe/s+ba2886Q8o1a7WosgqqAmt4u6R3IHOvVf5/PIeZrBJKrVptxjdjelP8Xwjq2ujWNtR3/HM1kjRlJi4xedvMRe4Rlxek0NDLC9hNd18RYi0EjzQ0bGSDDl0813yv6s6tcT6xHMzKvDcUcFRkX6BbxmoIcMsVeHM/ur6yRv834o/TT5IdiM9/wpkuICFOWIfM+Y8OWhiU6BK`,
			expected: `uCk7HocubT6KzJw2eXpSUItZFGkr7U+D89mJw70rxdqXP2JaG04SNjx3dd84G4bz+UVPPhPO2gBAx2vHI0xhgJG9T4vffAYh2D1kenmr+8gIHt6WDNeD+HwJeAbJYhfVFMJsTuIGlYIw8+I+TARK0vqjACyRwMDAndhXnDrk4E5U3hyjqS14XX0kIDZYM6FGFPXe/s+ba2886Q8o1a7WosgqqAmt4u6R3IHOvVf5/PIeZrBJKrVptxjdjelP8Xwjq2ujWNtR3/HM1kjRlJi4xedvMRe4Rlxek0NDLC9hNd18RYi0EjzQ0bGSDDl0813yv6s6tcT6xHMzKvDcUcFRkX6BbxmoIcMsVeHM/ur6yRv834o/TT5IdiM9/wpkuICFOWIfM+Y8OWhiU6BK`,
		},
		{
			in:       `Bb6Cqy6stJ0YhtPirRAQ8OXrPFKAeYHeuZXuC1qdHJRlweEzl4F2z/ZFG7hzr5NLZtzrRG3wm5TXl6Aua5G6v0WKcjJiS2V43WB8uY1BFK1d2y68c1gTRSF0u+VTThGjz+q/R6zE8HG8uchO+KPw64RehXDbPQ4uadiL+UwfZ4BzY1OHhvM5+2lVlibG+awtH6qzzx6zOWemTih932Lt9mMnm3FzEw7uGzPEYZ3aBV5xnbQ2a2N4UXIdm7RtIUiYFzHcLe5PZM/utJF8NdHKy0SPaKYkdXHli7g3tarzAabLZqLT4k7oemKYCn/eKRreZjqTB2E8Kc9Swf3jHDkmSvzOYE8wi1vQ3X7JtPcQ2O4muvpSa70NIE+XK1CgnnsL79Qzci1/1xgkBlNq`,
			expected: `Bb6Cqy6stJ0YhtPirRAQ8OXrPFKAeYHeuZXuC1qdHJRlweEzl4F2z/ZFG7hzr5NLZtzrRG3wm5TXl6Aua5G6v0WKcjJiS2V43WB8uY1BFK1d2y68c1gTRSF0u+VTThGjz+q/R6zE8HG8uchO+KPw64RehXDbPQ4uadiL+UwfZ4BzY1OHhvM5+2lVlibG+awtH6qzzx6zOWemTih932Lt9mMnm3FzEw7uGzPEYZ3aBV5xnbQ2a2N4UXIdm7RtIUiYFzHcLe5PZM/utJF8NdHKy0SPaKYkdXHli7g3tarzAabLZqLT4k7oemKYCn/eKRreZjqTB2E8Kc9Swf3jHDkmSvzOYE8wi1vQ3X7JtPcQ2O4muvpSa70NIE+XK1CgnnsL79Qzci1/1xgkBlNq`,
		},
		{
			in:       `FZNVr4nOICD1cNfAvQwZvZWi+P4I2Gubzrt+wK+7gLEY144BosgKeK7snwlA/vJjPAnkFW72APTBjY6kk4EOyoUef0MxRnZEU11vby5Ru19eixZBFB/SVXDJleLK0z3zXXE8U5Zl5RzLActHakG8Psvdt8TDscQc4MPZ1K7mXDhi7FQdpjRTwVxFyCFoybQ9WNJNGPsAkkm84NtFb4KjGpwVC70oq87tM2gYCrNgMhBfdBl0bnQHoNBCp76RKdpq1UAY01t1ipfgt7BoaAr0eTw1S32DezjfkAz04WyPTzkdBKd3b44rX9dXEbm6szAz0SjgztRPDJKSMELjq16W2Ua8d1AHq2Dz8JlsvGzi2jICUjpFsIfRmQ/STSvOT8VsaCFhwL1zDLbn5jCr`,
			expected: `FZNVr4nOICD1cNfAvQwZvZWi+P4I2Gubzrt+wK+7gLEY144BosgKeK7snwlA/vJjPAnkFW72APTBjY6kk4EOyoUef0MxRnZEU11vby5Ru19eixZBFB/SVXDJleLK0z3zXXE8U5Zl5RzLActHakG8Psvdt8TDscQc4MPZ1K7mXDhi7FQdpjRTwVxFyCFoybQ9WNJNGPsAkkm84NtFb4KjGpwVC70oq87tM2gYCrNgMhBfdBl0bnQHoNBCp76RKdpq1UAY01t1ipfgt7BoaAr0eTw1S32DezjfkAz04WyPTzkdBKd3b44rX9dXEbm6szAz0SjgztRPDJKSMELjq16W2Ua8d1AHq2Dz8JlsvGzi2jICUjpFsIfRmQ/STSvOT8VsaCFhwL1zDLbn5jCr`,
		},
		{
			in:       `RuiRkvYjH2FcCjNzFPT2PJWh7Q6vUbfMadMIEnw49GvzTmhk4OUFyjY13GL52JVyqdyFrnpgEOtXiTu88Cm+TiBI7JRh0jRs3VJRP3N+5GpyjKX7cJA46w8PrH3ovJo3PES7o8CSYKRa3eUs7BnFt7kUCvMqBBqIhTIKlnQd2JkMNnhhCcYdPygLx7E1Vg+H3KybcETsYWBeUVrhRl/RAyYJkn6LddjPuWkDdgIcnKhNvpQu4MMqF3YbzHgyTh7bdWjy1liZle7xR/uRbOrRIRKTxkUinQGEWyW3bbXOvPO71E7xyKywBanwg2FtvzOoRFRVF7V9mLzPSqdvbM7VMQoLFob2UgeNLbVHkWeQtEqQWIV5RMu3+knhoqGYxP/3Srszp0ELRQy/xyyD`,
			expected: `RuiRkvYjH2FcCjNzFPT2PJWh7Q6vUbfMadMIEnw49GvzTmhk4OUFyjY13GL52JVyqdyFrnpgEOtXiTu88Cm+TiBI7JRh0jRs3VJRP3N+5GpyjKX7cJA46w8PrH3ovJo3PES7o8CSYKRa3eUs7BnFt7kUCvMqBBqIhTIKlnQd2JkMNnhhCcYdPygLx7E1Vg+H3KybcETsYWBeUVrhRl/RAyYJkn6LddjPuWkDdgIcnKhNvpQu4MMqF3YbzHgyTh7bdWjy1liZle7xR/uRbOrRIRKTxkUinQGEWyW3bbXOvPO71E7xyKywBanwg2FtvzOoRFRVF7V9mLzPSqdvbM7VMQoLFob2UgeNLbVHkWeQtEqQWIV5RMu3+knhoqGYxP/3Srszp0ELRQy/xyyD`,
		},
		{
			in:       `mqBEVbNnL929CUA3sjkOmPB5dL0/a0spq8LgbIsJa22SfP580XduzUIKnCtdeC9TjPB/GEPp/LvEUFaLTUgPDQQGu3H5UCZyjVTAMHl45me/0qISEf903zFFqW5Lk3TS6iPrithqMMvhdK29Eg5OhhcoHS+ALpn0EjzUe86NywuFNb6ID4o8aF/ztZlKJegnpDAm3JuhCBauJ+0gcOB8GNdWd5a06qkokmwk1tgwWat7cQGFIH1NOvBwRMKhD51MJ7V28806a3zkOVwwhOiyyTXR+EcDA/aq5acX0yailLWB82g/2GR/DiaqNtusV+gpcMTNYemEv3c/xLkClJc29DSfTsJGKsmIDMqeBMM7RRBNinNAriY9iNX1UuHZLr/tUrRNrfuNT5CvvK1K`,
			expected: `mqBEVbNnL929CUA3sjkOmPB5dL0/a0spq8LgbIsJa22SfP580XduzUIKnCtdeC9TjPB/GEPp/LvEUFaLTUgPDQQGu3H5UCZyjVTAMHl45me/0qISEf903zFFqW5Lk3TS6iPrithqMMvhdK29Eg5OhhcoHS+ALpn0EjzUe86NywuFNb6ID4o8aF/ztZlKJegnpDAm3JuhCBauJ+0gcOB8GNdWd5a06qkokmwk1tgwWat7cQGFIH1NOvBwRMKhD51MJ7V28806a3zkOVwwhOiyyTXR+EcDA/aq5acX0yailLWB82g/2GR/DiaqNtusV+gpcMTNYemEv3c/xLkClJc29DSfTsJGKsmIDMqeBMM7RRBNinNAriY9iNX1UuHZLr/tUrRNrfuNT5CvvK1K`,
		},
		{
			in:       `IMcfbWZ/iCa/LDcvMlk6LEJ0gDe4ohy2Vi0pVBd9aqR5PnRj8zGit8G2rLuNUkDmQ95bMURasmaPw2Xjf6SQjRk8coIHDLtbg/YNQVMabE8pKd6EaFdsGWJkcFoonxhPR29aH0xvjC4Mp3cJX3mjqyVsOp9xdk6d0Y2hzV3W/oPCq0DV03pm7P3+jH2OzoVVIDYgG1FD12S03otJrCXuzDmE2LOQ0xwgBQ9sREBLXwQzUKfXH8ogZzjdR19pX9qe0rRKMNz8k5lqcF9R2z+XIS1QAfeV9xopXA0CeyrhtoOkXV2i8kBxyodDp7tIeOvbEfvaqZGJgaJyV8UMTDi7zjwNeVdyKa8USH7zrXSoCl+Ud5eflI9vxKS+u9Bt1ufBHJtULOCHGA2vimkU`,
			expected: `IMcfbWZ/iCa/LDcvMlk6LEJ0gDe4ohy2Vi0pVBd9aqR5PnRj8zGit8G2rLuNUkDmQ95bMURasmaPw2Xjf6SQjRk8coIHDLtbg/YNQVMabE8pKd6EaFdsGWJkcFoonxhPR29aH0xvjC4Mp3cJX3mjqyVsOp9xdk6d0Y2hzV3W/oPCq0DV03pm7P3+jH2OzoVVIDYgG1FD12S03otJrCXuzDmE2LOQ0xwgBQ9sREBLXwQzUKfXH8ogZzjdR19pX9qe0rRKMNz8k5lqcF9R2z+XIS1QAfeV9xopXA0CeyrhtoOkXV2i8kBxyodDp7tIeOvbEfvaqZGJgaJyV8UMTDi7zjwNeVdyKa8USH7zrXSoCl+Ud5eflI9vxKS+u9Bt1ufBHJtULOCHGA2vimkU`,
		},
		{
			in:       `AqC2sr44HVueGzgW13zHvJkqOEBWA8XA66ZEb3EoL1ehypSnJ07cFoWZlO8kf3k57L1fuHFWJ6quEdLXQaT9SJKHlUaYQvanvjbBlqWwaH3hODNsBGoK0DatpoQ+FxcSkdVE/ki3rbEUuJiZzU0BnDxH+Q6FiNsBaJuwau29w24MlD28ELJsjCcUVwtTQkaNtUxIlFKHLj0++T+IVrQH8KZlmVLvDefJ6llWbrFNVuh674HfKr/GEUatG6KI4gWNtGKKRYh76mMl5xH5qDfBZqxyRaKylJaDIYbx5xP5I4DDm4gOnxH+h/Pu6dq6FJ/U3eDio/KQ9xwFqTuyjH0BIRBsvWWgbTNURVBheq+am92YBhkj1QmdKTxQ9fQM55O8DpyWzRhky0NevM9j`,
			expected: `AqC2sr44HVueGzgW13zHvJkqOEBWA8XA66ZEb3EoL1ehypSnJ07cFoWZlO8kf3k57L1fuHFWJ6quEdLXQaT9SJKHlUaYQvanvjbBlqWwaH3hODNsBGoK0DatpoQ+FxcSkdVE/ki3rbEUuJiZzU0BnDxH+Q6FiNsBaJuwau29w24MlD28ELJsjCcUVwtTQkaNtUxIlFKHLj0++T+IVrQH8KZlmVLvDefJ6llWbrFNVuh674HfKr/GEUatG6KI4gWNtGKKRYh76mMl5xH5qDfBZqxyRaKylJaDIYbx5xP5I4DDm4gOnxH+h/Pu6dq6FJ/U3eDio/KQ9xwFqTuyjH0BIRBsvWWgbTNURVBheq+am92YBhkj1QmdKTxQ9fQM55O8DpyWzRhky0NevM9j`,
		},
		{
			in:       `qkFfS3WfLyj3QTQT9i/s57uOPQCTN1jrab8bwxaxyeYUlz2tEtYyKGGUufua8WzdBT2VvWTvH0JkK0LfUJ+vChvcnMFna+tEaCKCFMIOWMLYVZSJDcYMIqaIr8d0Bi2bpbVf5z4WNma0pbCKaXpkYgeg1Sb8HpKG0p0fAez7Q/QRASlvyM5vuIOH8/CM4fF5Ga6aWkTRG0lfxiyeZ2vi3q7uNmsZF490J79r/6tnPPXIIC4XGnijwho5NmhZG0XcQeyW5KnT7VmGACFdTHOb9oS5WxZZU29/oZ5Y23rBBoSDX/xZ1LNFiZk6Xfl4ih207jzogv+3nOro93JHQydNeKEwxOtbKqEe7WWJLDw/EzVdJTODrhBYKbjUce10XsavuiTvv+H1Qh4lo2Vx`,
			expected: `qkFfS3WfLyj3QTQT9i/s57uOPQCTN1jrab8bwxaxyeYUlz2tEtYyKGGUufua8WzdBT2VvWTvH0JkK0LfUJ+vChvcnMFna+tEaCKCFMIOWMLYVZSJDcYMIqaIr8d0Bi2bpbVf5z4WNma0pbCKaXpkYgeg1Sb8HpKG0p0fAez7Q/QRASlvyM5vuIOH8/CM4fF5Ga6aWkTRG0lfxiyeZ2vi3q7uNmsZF490J79r/6tnPPXIIC4XGnijwho5NmhZG0XcQeyW5KnT7VmGACFdTHOb9oS5WxZZU29/oZ5Y23rBBoSDX/xZ1LNFiZk6Xfl4ih207jzogv+3nOro93JHQydNeKEwxOtbKqEe7WWJLDw/EzVdJTODrhBYKbjUce10XsavuiTvv+H1Qh4lo2Vx`,
		},
		{
			in:       `O900/Gn82AjyLYqiWZ4ILXBBv/ZaXpTpQL0p9nv7gwF2MWsS2OWEImcVDa+1ElrjUumG6CVEv/rvax53krqJJDg+4Z/XcHxv58w6hNrXiWqFNjxlu5RZHvj1oQQXnS2n8qw8e/c+8ea2TiDIVr4OmgZz1G9uSPBeOZJvySqdgNPMpgfjZwkL2ez9/x31sLuQxi/FW3DFXU6kGSUjaq8g/iGXlaaAcQ0t9Gy+y005Z9wpr2JWWzishL+1JZp9D4SY/r3NHDphN4MNdLHMNBRPSIgfsaSqfLraIt+zWIycsd+nksVxtPv9wcyXy51E1qlHr6Uygz2VZYD9q9zyxEX4wRP2VEewHYUomL9d1F6gGG5fN3z82bQ4hI9uDirWhneWazUOQBRud5otPOm9`,
			expected: `O900/Gn82AjyLYqiWZ4ILXBBv/ZaXpTpQL0p9nv7gwF2MWsS2OWEImcVDa+1ElrjUumG6CVEv/rvax53krqJJDg+4Z/XcHxv58w6hNrXiWqFNjxlu5RZHvj1oQQXnS2n8qw8e/c+8ea2TiDIVr4OmgZz1G9uSPBeOZJvySqdgNPMpgfjZwkL2ez9/x31sLuQxi/FW3DFXU6kGSUjaq8g/iGXlaaAcQ0t9Gy+y005Z9wpr2JWWzishL+1JZp9D4SY/r3NHDphN4MNdLHMNBRPSIgfsaSqfLraIt+zWIycsd+nksVxtPv9wcyXy51E1qlHr6Uygz2VZYD9q9zyxEX4wRP2VEewHYUomL9d1F6gGG5fN3z82bQ4hI9uDirWhneWazUOQBRud5otPOm9`,
		},
		{
			in:       `C3c+d5Q9lyTafPLdelG1TKaLFinw1TOjyI6KkrQyHKkttfnO58WFvScl1TiRcB/iHxKahskoE2+VRLUIhctuDU4sUvQh/g9Arw0LAA4QTxuLFt01XYdigurz4FT15ox2oDGGGrRb3VGjDTXK1OWVJoLMW95EVqyMc9F+Fdej85LHE+8WesIfacjUQtTG1tzYVQTfubZq0+qxXws8QrxMLFtVE38tbeXo+Ok1/U5TUa6FjWflEfvKY3XVcl8RKkXua7fVz/Blj8Gh+dWe2cOxa0lpM75ZHyz9adQrB2Pb4571E4u2xI5un0R0MFJZBQuPDc1G5rPhyk+Hb4LRG3dS0m8IASQUOskv93z978L1+Abu9CLP6d6s5p+BzWxhMUqwQXC/CCpTywrkJ0RG`,
			expected: `C3c+d5Q9lyTafPLdelG1TKaLFinw1TOjyI6KkrQyHKkttfnO58WFvScl1TiRcB/iHxKahskoE2+VRLUIhctuDU4sUvQh/g9Arw0LAA4QTxuLFt01XYdigurz4FT15ox2oDGGGrRb3VGjDTXK1OWVJoLMW95EVqyMc9F+Fdej85LHE+8WesIfacjUQtTG1tzYVQTfubZq0+qxXws8QrxMLFtVE38tbeXo+Ok1/U5TUa6FjWflEfvKY3XVcl8RKkXua7fVz/Blj8Gh+dWe2cOxa0lpM75ZHyz9adQrB2Pb4571E4u2xI5un0R0MFJZBQuPDc1G5rPhyk+Hb4LRG3dS0m8IASQUOskv93z978L1+Abu9CLP6d6s5p+BzWxhMUqwQXC/CCpTywrkJ0RG`,
		},
		// Basic XSS
		{
			in:       `test<script>alert(document.cookie)</script>`,
			expected: `test`,
		},
		{
			in:       `<<<><<script src=http://fake-evil.ru/test.js>`,
			expected: `&lt;&lt;&lt;&gt;&lt;`,
		},
		{
			in:       `<script<script src=http://fake-evil.ru/test.js>>`,
			expected: `&gt;`,
		},
		{
			in:       `<SCRIPT/XSS SRC="http://ha.ckers.org/xss.js"></SCRIPT>`,
			expected: ``,
		},
		{
			in:       "<BODY onload!#$%&()*~+-_.,:;?@[/|\\]^`=alert(\"XSS\")>",
			expected: ``,
		},
		{
			in:       `<BODY ONLOAD=alert('XSS')>`,
			expected: ``,
		},
		{
			in:       `<iframe src=http://ha.ckers.org/scriptlet.html <`,
			expected: ``,
		},
		{
			in:       `<INPUT TYPE="IMAGE" SRC="javascript:alert('XSS');"">`,
			expected: `<input type="IMAGE">`,
		},
		{
			in:       `<a onblur="alert(secret)" href="http://www.google.com">Google</a>`,
			expected: `<a href="http://www.google.com">Google</a>`,
		},
		// IMG attacks
		{
			in:       `<img src="http://www.myspace.com/img.gif"/>`,
			expected: `<img src="http://www.myspace.com/img.gif"/>`,
		},
		{
			in:       `<img src=javascript:alert(document.cookie)>`,
			expected: ``,
		},
		{
			in:       `<IMG SRC=&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;&#58;&#97;&#108;&#101;&#114;&#116;&#40;&#39;&#88;&#83;&#83;&#39;&#41;>`,
			expected: ``,
		},
		{
			in:       `<IMG SRC='&#0000106&#0000097&#0000118&#0000097&#0000115&#0000099&#0000114&#0000105&#0000112&#0000116&#0000058&#0000097&#0000108&#0000101&#0000114&#0000116&#0000040&#0000039&#0000088&#0000083&#0000083&#0000039&#0000041'>`,
			expected: ``,
		},
		{
			in:       `<IMG SRC="jav&#x0D;ascript:alert('XSS');">`,
			expected: ``,
		},
		{
			in:       `<IMG SRC=&#0000106&#0000097&#0000118&#0000097&#0000115&#0000099&#0000114&#0000105&#0000112&#0000116&#0000058&#0000097&#0000108&#0000101&#0000114&#0000116&#0000040&#0000039&#0000088&#0000083&#0000083&#0000039&#0000041>`,
			expected: ``,
		},
		{
			in:       `<IMG SRC=&#x6A&#x61&#x76&#x61&#x73&#x63&#x72&#x69&#x70&#x74&#x3A&#x61&#x6C&#x65&#x72&#x74&#x28&#x27&#x58&#x53&#x53&#x27&#x29>`,
			expected: ``,
		},
		{
			in:       `<IMG SRC="javascript:alert('XSS')"`,
			expected: ``,
		},
		{
			in:       `<IMG LOWSRC="javascript:alert('XSS')">`,
			expected: ``,
		},
		{
			in:       `<BGSOUND SRC="javascript:alert('XSS');">`,
			expected: ``,
		},
		// HREF attacks
		{
			in:       `<LINK REL="stylesheet" HREF="javascript:alert('XSS');">`,
			expected: ``,
		},
		{
			in:       `<LINK REL="stylesheet" HREF="http://ha.ckers.org/xss.css">`,
			expected: ``,
		},
		{
			in:       `<STYLE>@import'http://ha.ckers.org/xss.css';</STYLE>`,
			expected: ``,
		},
		{
			in:       `<STYLE>BODY{-moz-binding:url("http://ha.ckers.org/xssmoz.xml#xss")}</STYLE>`,
			expected: ``,
		},
		{
			in:       `<STYLE>li {list-style-image: url("javascript:alert('XSS')");}</STYLE><UL><LI>XSS`,
			expected: `<ul><li>XSS`,
		},
		{
			in:       `<IMG SRC='vbscript:msgbox("XSS")'>`,
			expected: ``,
		},
		{
			in:       `<META HTTP-EQUIV="refresh" CONTENT="0; URL=http://;URL=javascript:alert('XSS');">`,
			expected: ``,
		},
		{
			in:       `<META HTTP-EQUIV="refresh" CONTENT="0;url=javascript:alert('XSS');">`,
			expected: ``,
		},
		{
			in:       `<META HTTP-EQUIV="refresh" CONTENT="0;url=data:text/html;base64,PHNjcmlwdD5hbGVydCgnWFNTJyk8L3NjcmlwdD4K">`,
			expected: ``,
		},
		{
			in:       `<IFRAME SRC="javascript:alert('XSS');"></IFRAME>`,
			expected: ``,
		},
		{
			in:       `<FRAMESET><FRAME SRC="javascript:alert('XSS');"></FRAMESET>`,
			expected: ``,
		},
		{
			in:       `<TABLE BACKGROUND="javascript:alert('XSS')">`,
			expected: ``,
		},
		{
			in:       `<TABLE><TD BACKGROUND="javascript:alert('XSS')">`,
			expected: `<td>`,
		},
		{
			in:       `<DIV STYLE="background-image: url(javascript:alert('XSS'))">`,
			expected: `<div>`,
		},
		{
			in:       `<DIV STYLE="width: expression(alert('XSS'));">`,
			expected: `<div>`,
		},
		{
			in:       `<IMG STYLE="xss:expr/*XSS*/ession(alert('XSS'))">`,
			expected: ``,
		},
		{
			in:       `<STYLE>@im\\port'\\ja\\vasc\\ript:alert("XSS")';</STYLE>`,
			expected: ``,
		},
		{
			in:       `<BASE HREF="javascript:alert('XSS');//">`,
			expected: ``,
		},
		{
			in:       `<BaSe hReF="http://arbitrary.com/">`,
			expected: ``,
		},
		{
			in:       `<OBJECT TYPE="text/x-scriptlet" DATA="http://ha.ckers.org/scriptlet.html"></OBJECT>`,
			expected: ``,
		},
		{
			in:       `<OBJECT classid=clsid:ae24fdae-03c6-11d1-8b76-0080c744f389><param name=url value=javascript:alert('XSS')></OBJECT>`,
			expected: ``,
		},
		{
			in:       `<EMBED SRC="http://ha.ckers.org/xss.swf" AllowScriptAccess="always"></EMBED>`,
			expected: ``,
		},
		{
			in:       `<EMBED SRC="data:image/svg+xml;base64,PHN2ZyB4bWxuczpzdmc9Imh0dH A6Ly93d3cudzMub3JnLzIwMDAvc3ZnIiB4bWxucz0iaHR0cDovL3d3dy53My5vcmcv MjAwMC9zdmciIHhtbG5zOnhsaW5rPSJodHRwOi8vd3d3LnczLm9yZy8xOTk5L3hs aW5rIiB2ZXJzaW9uPSIxLjAiIHg9IjAiIHk9IjAiIHdpZHRoPSIxOTQiIGhlaWdodD0iMjAw IiBpZD0ieHNzIj48c2NyaXB0IHR5cGU9InRleHQvZWNtYXNjcmlwdCI+YWxlcnQoIlh TUyIpOzwvc2NyaXB0Pjwvc3ZnPg==" type="image/svg+xml" AllowScriptAccess="always"></EMBED>`,
			expected: ``,
		},
		{
			in:       `<SCRIPT a=">" SRC="http://ha.ckers.org/xss.js"></SCRIPT>`,
			expected: ``,
		},
		{
			in:       `<SCRIPT a=">" '' SRC="http://ha.ckers.org/xss.js"></SCRIPT>`,
			expected: ``,
		},
		{
			in:       "<SCRIPT a=`>` SRC=\"http://ha.ckers.org/xss.js\"></SCRIPT>",
			expected: ``,
		},
		{
			in:       `<SCRIPT a=">'>" SRC="http://ha.ckers.org/xss.js"></SCRIPT>`,
			expected: ``,
		},
		{
			in:       `<SCRIPT>document.write("<SCRI");</SCRIPT>PT SRC="http://ha.ckers.org/xss.js"></SCRIPT>`,
			expected: `PT SRC=&#34;http://ha.ckers.org/xss.js&#34;&gt;`,
		},
		{
			in:       `<SCRIPT SRC=http://ha.ckers.org/xss.js`,
			expected: ``,
		},
		{
			in:       `<div/style=&#92&#45&#92&#109&#111&#92&#122&#92&#45&#98&#92&#105&#92&#110&#100&#92&#105&#110&#92&#103:&#92&#117&#114&#108&#40&#47&#47&#98&#117&#115&#105&#110&#101&#115&#115&#92&#105&#92&#110&#102&#111&#46&#99&#111&#46&#117&#107&#92&#47&#108&#97&#98&#115&#92&#47&#120&#98&#108&#92&#47&#120&#98&#108&#92&#46&#120&#109&#108&#92&#35&#120&#115&#115&#41&>`,
			expected: `<div>`,
		},
		{
			in:       `<a href='aim: &c:\\windows\\system32\\calc.exe' ini='C:\\Documents and Settings\\All Users\\Start Menu\\Programs\\Startup\\pwnd.bat'>`,
			expected: ``,
		},
		{
			in:       `<!--\n<A href=\n- --><a href=javascript:alert:document.domain>test-->`,
			expected: `test--&gt;`,
		},
		{
			in:       `<a></a style="xx:expr/**/ession(document.appendChild(document.createElement('script')).src='http://h4k.in/i.js')">`,
			expected: ``,
		},
		// CSS attacks
		{
			in:       `<div style="position:absolute">`,
			expected: `<div>`,
		},
		{
			in:       `<style>b { position:absolute }</style>`,
			expected: ``,
		},
		{
			in:       `<div style="z-index:25">test</div>`,
			expected: `<div>test</div>`,
		},
		{
			in:       `<style>z-index:25</style>`,
			expected: ``,
		},
		// Strings that cause issues for tokenizers
		{
			in:       `<a - href="http://www.test.com">`,
			expected: `<a href="http://www.test.com">`,
		},
		// Comments
		{
			in:       `text <!-- comment -->`,
			expected: `text `,
		},
		{
			in:       `<div>text <!-- comment --></div>`,
			expected: `<div>text </div>`,
		},
		{
			in:       `<div>text <!--[if IE]> comment <[endif]--></div>`,
			expected: `<div>text </div>`,
		},
		{
			in:       `<div>text <!--[if IE]> <!--[if gte 6]> comment <[endif]--><[endif]--></div>`,
			expected: `<div>text &lt;[endif]--&gt;</div>`,
		},
		{
			in:       `<div>text <!--[if IE]> <!-- IE specific --> comment <[endif]--></div>`,
			expected: `<div>text  comment &lt;[endif]--&gt;</div>`,
		},
		{
			in:       `<div>text <!-- [ if lte 6 ]>\ncomment <[ endif\n]--></div>`,
			expected: `<div>text </div>`,
		},
		{
			in:       `<div>text <![if !IE]> comment <![endif]></div>`,
			expected: `<div>text  comment </div>`,
		},
		{
			in:       `<div>text <![ if !IE]> comment <![endif]></div>`,
			expected: `<div>text  comment </div>`,
		},
	}

	// These tests are run concurrently to enable the race detector to pick up
	// potential issues
	wg := sync.WaitGroup{}
	wg.Add(len(tests))
	for ii, tt := range tests {
		go func(ii int, tt test) {
			out := p.Sanitize(tt.in)
			if out != tt.expected {
				t.Errorf(
					"test %d failed;\ninput   : %s\noutput  : %s\nexpected: %s",
					ii,
					tt.in,
					out,
					tt.expected,
				)
			}
			wg.Done()
		}(ii, tt)
	}
	wg.Wait()
}

func TestXSS(t *testing.T) {
	p := UGCPolicy()

	tests := []test{
		{
			in:       `<A HREF="javascript:document.location='http://www.google.com/'">XSS</A>`,
			expected: `XSS`,
		},
		{
			in: `<A HREF="h
tt	p://6	6.000146.0x7.147/">XSS</A>`,
			expected: `XSS`,
		},
		{
			in:       `<SCRIPT>document.write("<SCRI");</SCRIPT>PT SRC="http://ha.ckers.org/xss.js"></SCRIPT>`,
			expected: `PT SRC=&#34;http://ha.ckers.org/xss.js&#34;&gt;`,
		},
		{
			in:       `<SCRIPT a=">'>" SRC="http://ha.ckers.org/xss.js"></SCRIPT>`,
			expected: ``,
		},
		{
			in:       "<SCRIPT a=`>` SRC=\"http://ha.ckers.org/xss.js\"></SCRIPT>",
			expected: ``,
		},
		{
			in:       `<SCRIPT "a='>'" SRC="http://ha.ckers.org/xss.js"></SCRIPT>`,
			expected: ``,
		},
		{
			in:       `<SCRIPT a=">" '' SRC="http://ha.ckers.org/xss.js"></SCRIPT>`,
			expected: ``,
		},
		{
			in:       `<SCRIPT =">" SRC="http://ha.ckers.org/xss.js"></SCRIPT>`,
			expected: ``,
		},
		{
			in:       `<SCRIPT a=">" SRC="http://ha.ckers.org/xss.js"></SCRIPT>`,
			expected: ``,
		},
		{
			in:       `<HEAD><META HTTP-EQUIV="CONTENT-TYPE" CONTENT="text/html; charset=UTF-7"> </HEAD>+ADw-SCRIPT+AD4-alert('XSS')`,
			expected: ` +ADw-SCRIPT+AD4-alert(&#39;XSS&#39;)`,
		},
		{
			in:       `<META HTTP-EQUIV="Set-Cookie" Content="USERID=<SCRIPT>alert('XSS')</SCRIPT>">`,
			expected: ``,
		},
		{
			in: `<? echo('<SCR)';
echo('IPT>alert("XSS")</SCRIPT>'); ?>`,
			expected: `alert(&#34;XSS&#34;)&#39;); ?&gt;`,
		},
		{
			in:       `<!--#exec cmd="/bin/echo '<SCR'"--><!--#exec cmd="/bin/echo 'IPT SRC=http://ha.ckers.org/xss.js></SCRIPT>'"-->`,
			expected: ``,
		},
		{
			in: `<HTML><BODY>
<?xml:namespace prefix="t" ns="urn:schemas-microsoft-com:time">
<?import namespace="t" implementation="#default#time2">
<t:set attributeName="innerHTML" to="XSS<SCRIPT DEFER>alert("XSS")</SCRIPT>">
</BODY></HTML>`,
			expected: "\n\n\n&#34;&gt;\n",
		},
		{
			in: `<XML SRC="xsstest.xml" ID=I></XML>
<SPAN DATASRC=#I DATAFLD=C DATAFORMATAS=HTML></SPAN>`,
			expected: `
<span></span>`,
		},
		{
			in: `<XML ID="xss"><I><B><IMG SRC="javas<!-- -->cript:alert('XSS')"></B></I></XML>
<SPAN DATASRC="#xss" DATAFLD="B" DATAFORMATAS="HTML"></SPAN>`,
			expected: `<i><b></b></i>
<span></span>`,
		},
		{
			in:       `<EMBED SRC="data:image/svg+xml;base64,PHN2ZyB4bWxuczpzdmc9Imh0dH A6Ly93d3cudzMub3JnLzIwMDAvc3ZnIiB4bWxucz0iaHR0cDovL3d3dy53My5vcmcv MjAwMC9zdmciIHhtbG5zOnhsaW5rPSJodHRwOi8vd3d3LnczLm9yZy8xOTk5L3hs aW5rIiB2ZXJzaW9uPSIxLjAiIHg9IjAiIHk9IjAiIHdpZHRoPSIxOTQiIGhlaWdodD0iMjAw IiBpZD0ieHNzIj48c2NyaXB0IHR5cGU9InRleHQvZWNtYXNjcmlwdCI+YWxlcnQoIlh TUyIpOzwvc2NyaXB0Pjwvc3ZnPg==" type="image/svg+xml" AllowScriptAccess="always"></EMBED>`,
			expected: ``,
		},
		{
			in:       `<OBJECT TYPE="text/x-scriptlet" DATA="http://ha.ckers.org/scriptlet.html"></OBJECT>`,
			expected: ``,
		},
		{
			in:       `<BASE HREF="javascript:alert('XSS');//">`,
			expected: ``,
		},
		{
			in:       `<!--[if gte IE 4]><SCRIPT>alert('XSS');</SCRIPT><![endif]-->`,
			expected: ``,
		},
		{
			in:       `<DIV STYLE="width: expression(alert('XSS'));">`,
			expected: `<div>`,
		},
		{
			in:       `<DIV STYLE="background-image: url(&#1;javascript:alert('XSS'))">`,
			expected: `<div>`,
		},
		{
			in:       `<DIV STYLE="background-image:\0075\0072\006C\0028'\006a\0061\0076\0061\0073\0063\0072\0069\0070\0074\003a\0061\006c\0065\0072\0074\0028.1027\0058.1053\0053\0027\0029'\0029">`,
			expected: `<div>`,
		},
		{
			in:       `<DIV STYLE="background-image: url(javascript:alert('XSS'))">`,
			expected: `<div>`,
		},
		{
			in:       `<TABLE><TD BACKGROUND="javascript:alert('XSS')">`,
			expected: `<table><td>`,
		},
		{
			in:       `<TABLE BACKGROUND="javascript:alert('XSS')">`,
			expected: `<table>`,
		},
		{
			in:       `<FRAMESET><FRAME SRC="javascript:alert('XSS');"></FRAMESET>`,
			expected: ``,
		},
		{
			in:       `<IFRAME SRC=# onmouseover="alert(document.cookie)"></IFRAME>`,
			expected: ``,
		},
		{
			in:       `<IFRAME SRC="javascript:alert('XSS');"></IFRAME>`,
			expected: ``,
		},
		{
			in:       `<META HTTP-EQUIV="refresh" CONTENT="0; URL=http://;URL=javascript:alert('XSS');">`,
			expected: ``,
		},
		{
			in:       `<META HTTP-EQUIV="refresh" CONTENT="0;url=data:text/html base64,PHNjcmlwdD5hbGVydCgnWFNTJyk8L3NjcmlwdD4K">`,
			expected: ``,
		},
		{
			in:       `<META HTTP-EQUIV="refresh" CONTENT="0;url=javascript:alert('XSS');">`,
			expected: ``,
		},
		{
			in:       `<XSS STYLE="behavior: url(xss.htc);">`,
			expected: ``,
		},
		{
			in:       `<XSS STYLE="xss:expression(alert('XSS'))">`,
			expected: ``,
		},
		{
			in:       `<STYLE type="text/css">BODY{background:url("javascript:alert('XSS')")}</STYLE>`,
			expected: ``,
		},
		{
			in:       `<STYLE>.XSS{background-image:url("javascript:alert('XSS')");}</STYLE><A CLASS=XSS></A>`,
			expected: ``,
		},
		{
			in:       `<STYLE TYPE="text/javascript">alert('XSS');</STYLE>`,
			expected: ``,
		},
		{
			in:       `<IMG STYLE="xss:expr/*XSS*/ession(alert('XSS'))">`,
			expected: ``,
		},
		{
			in:       `<STYLE>@im\port'\ja\vasc\ript:alert("XSS")';</STYLE>`,
			expected: ``,
		},
		{
			in:       `<STYLE>BODY{-moz-binding:url("http://ha.ckers.org/xssmoz.xml#xss")}</STYLE>`,
			expected: ``,
		},
		{
			in:       `<META HTTP-EQUIV="Link" Content="<http://ha.ckers.org/xss.css>; REL=stylesheet">`,
			expected: ``,
		},
		{
			in:       `<STYLE>@import'http://ha.ckers.org/xss.css';</STYLE>`,
			expected: ``,
		},
		{
			in:       `<LINK REL="stylesheet" HREF="http://ha.ckers.org/xss.css">`,
			expected: ``,
		},
		{
			in:       `<LINK REL="stylesheet" HREF="javascript:alert('XSS');">`,
			expected: ``,
		},
		{
			in:       `<BR SIZE="&{alert('XSS')}">`,
			expected: `<br>`,
		},
		{
			in:       `<BGSOUND SRC="javascript:alert('XSS');">`,
			expected: ``,
		},
		{
			in:       `<BODY ONLOAD=alert('XSS')>`,
			expected: ``,
		},
		{
			in:       `<STYLE>li {list-style-image: url("javascript:alert('XSS')");}</STYLE><UL><LI>XSS</br>`,
			expected: `<ul><li>XSS</br>`,
		},
		{
			in:       `<IMG LOWSRC="javascript:alert('XSS')">`,
			expected: ``,
		},
		{
			in:       `<IMG DYNSRC="javascript:alert('XSS')">`,
			expected: ``,
		},
		{
			in:       `<BODY BACKGROUND="javascript:alert('XSS')">`,
			expected: ``,
		},
		{
			in:       `<INPUT TYPE="IMAGE" SRC="javascript:alert('XSS');">`,
			expected: ``,
		},
		{
			in:       `</TITLE><SCRIPT>alert("XSS");</SCRIPT>`,
			expected: ``,
		},
		{
			in:       `\";alert('XSS');//`,
			expected: `\&#34;;alert(&#39;XSS&#39;);//`,
		},
		{
			in:       `<iframe src=http://ha.ckers.org/scriptlet.html <`,
			expected: ``,
		},
		{
			in:       `<SCRIPT SRC=http://ha.ckers.org/xss.js?< B >`,
			expected: ``,
		},
		{
			in:       `<<SCRIPT>alert("XSS");//<</SCRIPT>`,
			expected: `&lt;`,
		},
		{
			in:       "<BODY onload!#$%&()*~+-_.,:;?@[/|\\]^`=alert(\"XSS\")>",
			expected: ``,
		},
		{
			in:       `<SCRIPT/SRC="http://ha.ckers.org/xss.js"></SCRIPT>`,
			expected: ``,
		},
		{
			in:       `<SCRIPT/XSS SRC="http://ha.ckers.org/xss.js"></SCRIPT>`,
			expected: ``,
		},
		{
			in:       `<IMG SRC=" &#14;  javascript:alert('XSS');">`,
			expected: ``,
		},
		{
			in:       `<IMG SRC="jav&#x0A;ascript:alert('XSS');">`,
			expected: ``,
		},
		{
			in:       `<IMG SRC="jav&#x09;ascript:alert('XSS');">`,
			expected: ``,
		},
		{
			in:       `<IMG SRC="jav	ascript:alert('XSS');">`,
			expected: ``,
		},
		{
			in:       `<IMG SRC=&#x6A&#x61&#x76&#x61&#x73&#x63&#x72&#x69&#x70&#x74&#x3A&#x61&#x6C&#x65&#x72&#x74&#x28&#x27&#x58&#x53&#x53&#x27&#x29>`,
			expected: ``,
		},
		{
			in: `<IMG SRC=&#0000106&#0000097&#0000118&#0000097&#0000115&#0000099&#0000114&#0000105&#0000112&#0000116&#0000058&#0000097&
#0000108&#0000101&#0000114&#0000116&#0000040&#0000039&#0000088&#0000083&#0000083&#0000039&#0000041>`,
			expected: ``,
		},
		{
			in: `<IMG SRC=&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;&#58;&#97;&#108;&#101;&#114;&#116;&#40;
&#39;&#88;&#83;&#83;&#39;&#41;>`,
			expected: ``,
		},
		{
			in:       `<IMG SRC=/ onerror="alert(String.fromCharCode(88,83,83))"></img>`,
			expected: `<img src="/"></img>`,
		},
		{
			in:       `<IMG onmouseover="alert('xxs')">`,
			expected: ``,
		},
		{
			in:       `<IMG SRC= onmouseover="alert('xxs')">`,
			expected: `<img src="onmouseover=%22alert%28%27xxs%27%29%22">`,
		},
		{
			in:       `<IMG SRC=# onmouseover="alert('xxs')">`,
			expected: ``,
		},
		{
			in:       `<IMG SRC=javascript:alert(String.fromCharCode(88,83,83))>`,
			expected: ``,
		},
		{
			in:       `<IMG """><SCRIPT>alert("XSS")</SCRIPT>">`,
			expected: `&#34;&gt;`,
		},
		{
			in:       `<IMG SRC=javascript:alert("XSS")>`,
			expected: ``,
		},
		{
			in:       `<IMG SRC=JaVaScRiPt:alert('XSS')>`,
			expected: ``,
		},
		{
			in:       `<IMG SRC=javascript:alert('XSS')>`,
			expected: ``,
		},
		{
			in:       `<IMG SRC="javascript:alert('XSS');">`,
			expected: ``,
		},
		{
			in:       `<SCRIPT SRC=http://ha.ckers.org/xss.js></SCRIPT>`,
			expected: ``,
		},
		{
			in:       `'';!--"<XSS>=&{()}`,
			expected: `&#39;&#39;;!--&#34;=&amp;{()}`,
		},
		{
			in:       `';alert(String.fromCharCode(88,83,83))//';alert(String.fromCharCode(88,83,83))//";alert(String.fromCharCode(88,83,83))//";alert(String.fromCharCode(88,83,83))//--></SCRIPT>">'><SCRIPT>alert(String.fromCharCode(88,83,83))</SCRIPT>`,
			expected: `&#39;;alert(String.fromCharCode(88,83,83))//&#39;;alert(String.fromCharCode(88,83,83))//&#34;;alert(String.fromCharCode(88,83,83))//&#34;;alert(String.fromCharCode(88,83,83))//--&gt;&#34;&gt;&#39;&gt;`,
		},
	}

	// These tests are run concurrently to enable the race detector to pick up
	// potential issues
	wg := sync.WaitGroup{}
	wg.Add(len(tests))
	for ii, tt := range tests {
		go func(ii int, tt test) {
			out := p.Sanitize(tt.in)
			if out != tt.expected {
				t.Errorf(
					"test %d failed;\ninput   : %s\noutput  : %s\nexpected: %s",
					ii,
					tt.in,
					out,
					tt.expected,
				)
			}
			wg.Done()
		}(ii, tt)
	}
	wg.Wait()
}

func TestAllowNoAttrs(t *testing.T) {
	input := "<tag>test</tag>"
	outputFail := "test"
	outputOk := input

	p := NewPolicy()
	p.AllowElements("tag")

	if output := p.Sanitize(input); output != outputFail {
		t.Errorf(
			"test failed;\ninput   : %s\noutput  : %s\nexpected: %s",
			input,
			output,
			outputFail,
		)
	}

	p.AllowNoAttrs().OnElements("tag")

	if output := p.Sanitize(input); output != outputOk {
		t.Errorf(
			"test failed;\ninput   : %s\noutput  : %s\nexpected: %s",
			input,
			output,
			outputOk,
		)
	}
}

func TestSkipElementsContent(t *testing.T) {
	p := NewPolicy()
	input := "<tag>test</tag>"
	assert.Equal(t, "test", p.Sanitize(input))

	p.SkipElementsContent("tag")
	assert.Empty(t, p.Sanitize(input))

	p.AllowNoAttrs().OnElements("tag")
	assert.Equal(t, "<tag></tag>", p.Sanitize(input))

	p.AllowElementsContent("tag")
	assert.Equal(t, input, p.Sanitize(input))

	input2 := "<tag><p>test</p></tag>"
	assert.Equal(t, input, p.Sanitize(input2))

	input = input2
	p.AllowElements("p")
	assert.Equal(t, input, p.Sanitize(input))

	p.SkipElementsContent("tag")
	assert.Equal(t, "<tag></tag>", p.Sanitize(input))

	input = `<iframe src="https://www.youtube.com/"><p>test</p></iframe>`
	p.AllowAttrs("src").OnElements("iframe")
	assert.Equal(t,
		`<iframe src="https://www.youtube.com/"></iframe>`,
		p.Sanitize(input))

	p.AllowElementsContent("iframe")
	assert.Equal(t,
		`<iframe src="https://www.youtube.com/">&lt;p&gt;test&lt;/p&gt;</iframe>`,
		p.Sanitize(input))
}

func TestTagSkipClosingTagNested(t *testing.T) {
	input := "<tag1><tag2><tag3>text</tag3></tag2></tag1>"
	outputOk := "<tag2>text</tag2>"

	p := NewPolicy()
	p.AllowElements("tag1", "tag3")
	p.AllowNoAttrs().OnElements("tag2")

	if output := p.Sanitize(input); output != outputOk {
		t.Errorf(
			"test failed;\ninput   : %s\noutput  : %s\nexpected: %s",
			input,
			output,
			outputOk,
		)
	}
}

func TestAddSpaces(t *testing.T) {
	p := UGCPolicy()
	p.AddSpaceWhenStrippingTag(true)

	tests := []test{
		{
			in:       `<foo>Hello</foo><bar>World</bar>`,
			expected: ` Hello  World `,
		},
		{
			in:       `<p>Hello</p><bar>World</bar>`,
			expected: `<p>Hello</p> World `,
		},
		{
			in:       `<p>Hello</p><foo /><p>World</p>`,
			expected: `<p>Hello</p> <p>World</p>`,
		},
	}

	// These tests are run concurrently to enable the race detector to pick up
	// potential issues
	wg := sync.WaitGroup{}
	wg.Add(len(tests))
	for ii, tt := range tests {
		go func(ii int, tt test) {
			out := p.Sanitize(tt.in)
			if out != tt.expected {
				t.Errorf(
					"test %d failed;\ninput   : %s\noutput  : %s\nexpected: %s",
					ii,
					tt.in,
					out,
					tt.expected,
				)
			}
			wg.Done()
		}(ii, tt)
	}
	wg.Wait()
}

func TestTargetBlankNoOpener(t *testing.T) {
	p := UGCPolicy()
	p.AddTargetBlankToFullyQualifiedLinks(true)
	p.AllowAttrs("target").Matching(Paragraph).OnElements("a")

	tests := []test{
		{
			in:       `<a href="/path" />`,
			expected: `<a href="/path" rel="nofollow"/>`,
		},
		{
			in:       `<a href="/path" target="_blank" />`,
			expected: `<a href="/path" target="_blank" rel="nofollow noopener"/>`,
		},
		{
			in:       `<a href="/path" target="foo" />`,
			expected: `<a href="/path" target="foo" rel="nofollow"/>`,
		},
		{
			in:       `<a href="https://www.google.com/" />`,
			expected: `<a href="https://www.google.com/" target="_blank" rel="nofollow noopener"/>`,
		},
		{
			in:       `<a href="https://www.google.com/" target="_blank"/>`,
			expected: `<a href="https://www.google.com/" target="_blank" rel="nofollow noopener"/>`,
		},
		{
			in:       `<a href="https://www.google.com/" rel="nofollow"/>`,
			expected: `<a href="https://www.google.com/" target="_blank" rel="nofollow noopener"/>`,
		},
		{
			in:       `<a href="https://www.google.com/" rel="noopener"/>`,
			expected: `<a href="https://www.google.com/" target="_blank" rel="nofollow noopener"/>`,
		},
		{
			in:       `<a href="https://www.google.com/" rel="noopener nofollow" />`,
			expected: `<a href="https://www.google.com/" target="_blank" rel="nofollow noopener"/>`,
		},
		{
			in:       `<a href="https://www.google.com/" target="foo" />`,
			expected: `<a href="https://www.google.com/" target="_blank" rel="nofollow noopener"/>`,
		},
	}

	// These tests are run concurrently to enable the race detector to pick up
	// potential issues
	wg := sync.WaitGroup{}
	wg.Add(len(tests))
	for ii, tt := range tests {
		go func(ii int, tt test) {
			out := p.Sanitize(tt.in)
			if out != tt.expected {
				t.Errorf(
					"test %d failed;\ninput   : %s\noutput  : %s\nexpected: %s",
					ii,
					tt.in,
					out,
					tt.expected,
				)
			}
			wg.Done()
		}(ii, tt)
	}
	wg.Wait()
}

func TestIFrameSandbox(t *testing.T) {
	p := NewPolicy()
	p.AllowAttrs("sandbox").OnElements("iframe")
	p.RequireSandboxOnIFrame(SandboxAllowForms, SandboxAllowPopups)

	in := `<iframe src="http://example.com" sandbox="allow-forms allow-downloads allow-downloads allow-popups"></iframe>`
	expected := `<iframe sandbox="allow-forms allow-popups"></iframe>`
	out := p.Sanitize(in)
	if out != expected {
		t.Errorf(
			"test failed;\ninput   : %s\noutput  : %s\nexpected: %s",
			in,
			out,
			expected,
		)
	}
}

func TestIssue111ScriptTags(t *testing.T) {
	assert.Equal(t, "script", strings.ToLower("scr\u0130pt"))

	p1 := NewPolicy()
	in := `<scr\u0130pt>&lt;script&gt;alert(document.domain)&lt;/script&gt;`
	expected := `&lt;script&gt;alert(document.domain)&lt;/script&gt;`
	assert.Equal(t, expected, p1.Sanitize(in))

	p2 := UGCPolicy()
	expected = `&lt;script&gt;alert(document.domain)&lt;/script&gt;`
	assert.Equal(t, expected, p2.Sanitize(in))

	p3 := UGCPolicy().AllowElements("script")
	expected = `&lt;script&gt;alert(document.domain)&lt;/script&gt;`
	assert.Equal(t, expected, p3.Sanitize(in))
}

func TestQuotes(t *testing.T) {
	p := UGCPolicy()

	tests := []test{
		{
			in:       `noquotes`,
			expected: `noquotes`,
		},
		{
			in:       `"singlequotes"`,
			expected: `&#34;singlequotes&#34;`,
		},
		{
			in:       `""doublequotes""`,
			expected: `&#34;&#34;doublequotes&#34;&#34;`,
		},
	}

	// These tests are run concurrently to enable the race detector to pick up
	// potential issues
	wg := sync.WaitGroup{}
	wg.Add(len(tests))
	for ii, tt := range tests {
		go func(ii int, tt test) {
			out := p.Sanitize(tt.in)
			if out != tt.expected {
				t.Errorf(
					"test %d failed;\ninput   : %s\noutput  : %s\nexpected: %s",
					ii,
					tt.in,
					out,
					tt.expected,
				)
			}
			wg.Done()
		}(ii, tt)
	}
	wg.Wait()
}

func TestComments(t *testing.T) {
	p := UGCPolicy()

	tests := []test{
		{
			in:       `1 <!-- 2 --> 3`,
			expected: `1  3`,
		},
		{
			in:       `<!--[if gte mso 9]>Hello<![endif]-->`,
			expected: ``,
		},
	}

	// These tests are run concurrently to enable the race detector to pick up
	// potential issues
	wg := sync.WaitGroup{}
	wg.Add(len(tests))
	for ii, tt := range tests {
		go func(ii int, tt test) {
			out := p.Sanitize(tt.in)
			if out != tt.expected {
				t.Errorf(
					"test %d failed;\ninput   : %s\noutput  : %s\nexpected: %s",
					ii,
					tt.in,
					out,
					tt.expected,
				)
			}
			wg.Done()
		}(ii, tt)
	}
	wg.Wait()

	p.AllowComments()

	tests = []test{
		{
			in:       `1 <!-- 2 --> 3`,
			expected: `1 <!-- 2 --> 3`,
		},
		// Note that prior to go1.19 this test worked and preserved HTML comments
		// of the style used by Microsoft to create browser specific sections.
		//
		// However as @zhsj notes https://github.com/microcosm-cc/bluemonday/pull/148
		// the commit https://github.com/golang/net/commit/06994584 broke this.
		//
		// I haven't found a way to allow MS style comments without creating a risk
		// for every user of bluemonday that utilises .AllowComments()
		{
			in:       `<!--[if gte mso 9]>Hello<![endif]-->`,
			expected: `<!--[if gte mso 9]>Hello<![endif]-->`,
		},
	}

	// These tests are run concurrently to enable the race detector to pick up
	// potential issues
	wg = sync.WaitGroup{}
	wg.Add(len(tests))
	for ii, tt := range tests {
		go func(ii int, tt test) {
			out := p.Sanitize(tt.in)
			if out != tt.expected {
				t.Errorf(
					"test %d failed;\ninput   : %s\noutput  : %s\nexpected: %s",
					ii,
					tt.in,
					out,
					tt.expected,
				)
			}
			wg.Done()
		}(ii, tt)
	}
	wg.Wait()
}

func TestAdditivePolicies(t *testing.T) {
	t.Run("AllowAttrs", func(t *testing.T) {
		p := NewPolicy()
		p.AllowAttrs("class").Matching(regexp.MustCompile("red")).OnElements("span")

		t.Run("red", func(t *testing.T) {
			tests := []test{
				{
					in:       `<span class="red">test</span>`,
					expected: `<span class="red">test</span>`,
				},
				{
					in:       `<span class="green">test</span>`,
					expected: `<span>test</span>`,
				},
				{
					in:       `<span class="blue">test</span>`,
					expected: `<span>test</span>`,
				},
			}

			for ii, tt := range tests {
				out := p.Sanitize(tt.in)
				if out != tt.expected {
					t.Errorf(
						"test %d failed;\ninput   : %s\noutput  : %s\nexpected: %s",
						ii,
						tt.in,
						out,
						tt.expected,
					)
				}
			}
		})

		p.AllowAttrs("class").Matching(regexp.MustCompile("green")).OnElements("span")

		t.Run("green", func(t *testing.T) {
			tests := []test{
				{
					in:       `<span class="red">test</span>`,
					expected: `<span class="red">test</span>`,
				},
				{
					in:       `<span class="green">test</span>`,
					expected: `<span class="green">test</span>`,
				},
				{
					in:       `<span class="blue">test</span>`,
					expected: `<span>test</span>`,
				},
			}

			for ii, tt := range tests {
				out := p.Sanitize(tt.in)
				if out != tt.expected {
					t.Errorf(
						"test %d failed;\ninput   : %s\noutput  : %s\nexpected: %s",
						ii,
						tt.in,
						out,
						tt.expected,
					)
				}
			}
		})

		p.AllowAttrs("class").Matching(regexp.MustCompile("yellow")).OnElements("span")

		t.Run("yellow", func(t *testing.T) {
			tests := []test{
				{
					in:       `<span class="red">test</span>`,
					expected: `<span class="red">test</span>`,
				},
				{
					in:       `<span class="green">test</span>`,
					expected: `<span class="green">test</span>`,
				},
				{
					in:       `<span class="blue">test</span>`,
					expected: `<span>test</span>`,
				},
			}

			for ii, tt := range tests {
				out := p.Sanitize(tt.in)
				if out != tt.expected {
					t.Errorf(
						"test %d failed;\ninput   : %s\noutput  : %s\nexpected: %s",
						ii,
						tt.in,
						out,
						tt.expected,
					)
				}
			}
		})
	})

	t.Run("AllowURLSchemeWithCustomPolicy", func(t *testing.T) {
		p := NewPolicy()
		p.AllowAttrs("href").OnElements("a")

		p.AllowURLSchemeWithCustomPolicy(
			"http",
			func(url *url.URL) bool {
				return url.Hostname() == "example.org"
			},
		)

		t.Run("example.org", func(t *testing.T) {
			tests := []test{
				{
					in:       `<a href="http://example.org/">test</a>`,
					expected: `<a href="http://example.org/">test</a>`,
				},
				{
					in:       `<a href="http://example2.org/">test</a>`,
					expected: `test`,
				},
				{
					in:       `<a href="http://example4.org/">test</a>`,
					expected: `test`,
				},
			}

			for ii, tt := range tests {
				out := p.Sanitize(tt.in)
				if out != tt.expected {
					t.Errorf(
						"test %d failed;\ninput   : %s\noutput  : %s\nexpected: %s",
						ii,
						tt.in,
						out,
						tt.expected,
					)
				}
			}
		})

		p.AllowURLSchemeWithCustomPolicy(
			"http",
			func(url *url.URL) bool {
				return url.Hostname() == "example2.org"
			},
		)

		t.Run("example2.org", func(t *testing.T) {
			tests := []test{
				{
					in:       `<a href="http://example.org/">test</a>`,
					expected: `<a href="http://example.org/">test</a>`,
				},
				{
					in:       `<a href="http://example2.org/">test</a>`,
					expected: `<a href="http://example2.org/">test</a>`,
				},
				{
					in:       `<a href="http://example4.org/">test</a>`,
					expected: `test`,
				},
			}

			for ii, tt := range tests {
				out := p.Sanitize(tt.in)
				if out != tt.expected {
					t.Errorf(
						"test %d failed;\ninput   : %s\noutput  : %s\nexpected: %s",
						ii,
						tt.in,
						out,
						tt.expected,
					)
				}
			}
		})

		p.AllowURLSchemeWithCustomPolicy(
			"http",
			func(url *url.URL) bool {
				return url.Hostname() == "example3.org"
			},
		)

		t.Run("example3.org", func(t *testing.T) {
			tests := []test{
				{
					in:       `<a href="http://example.org/">test</a>`,
					expected: `<a href="http://example.org/">test</a>`,
				},
				{
					in:       `<a href="http://example2.org/">test</a>`,
					expected: `<a href="http://example2.org/">test</a>`,
				},
				{
					in:       `<a href="http://example4.org/">test</a>`,
					expected: `test`,
				},
			}

			for ii, tt := range tests {
				out := p.Sanitize(tt.in)
				if out != tt.expected {
					t.Errorf(
						"test %d failed;\ninput   : %s\noutput  : %s\nexpected: %s",
						ii,
						tt.in,
						out,
						tt.expected,
					)
				}
			}
		})
	})
}

func TestHrefSanitization(t *testing.T) {
	tests := []test{
		{
			in:       `abc<a href="https://abc&quot;&gt;<script&gt;alert(1)<&#x2f;script/">CLICK`,
			expected: `abc<a href="https://abc&#34;&gt;&lt;script&gt;alert(1)&lt;/script/" rel="nofollow">CLICK`,
		},
		{
			in:       `<a href="https://abc&quot;&gt;<script&gt;alert(1)<&#x2f;script/">`,
			expected: `<a href="https://abc&#34;&gt;&lt;script&gt;alert(1)&lt;/script/" rel="nofollow">`,
		},
	}

	p := UGCPolicy()

	// These tests are run concurrently to enable the race detector to pick up
	// potential issues
	wg := sync.WaitGroup{}
	wg.Add(len(tests))
	for ii, tt := range tests {
		go func(ii int, tt test) {
			out := p.Sanitize(tt.in)
			if out != tt.expected {
				t.Errorf(
					"test %d failed;\ninput   : %s\noutput  : %s\nexpected: %s",
					ii,
					tt.in,
					out,
					tt.expected,
				)
			}
			wg.Done()
		}(ii, tt)
	}
	wg.Wait()
}

func TestInsertionModeSanitization(t *testing.T) {
	tests := []test{
		{
			in:       `<select><option><style><script>alert(1)</script>`,
			expected: `<select><option>`,
		},
	}

	p := UGCPolicy()
	p.AllowElements("select", "option", "style")

	// These tests are run concurrently to enable the race detector to pick up
	// potential issues
	wg := sync.WaitGroup{}
	wg.Add(len(tests))
	for ii, tt := range tests {
		go func(ii int, tt test) {
			out := p.Sanitize(tt.in)
			if out != tt.expected {
				t.Errorf(
					"test %d failed;\ninput   : %s\noutput  : %s\nexpected: %s",
					ii,
					tt.in,
					out,
					tt.expected,
				)
			}
			wg.Done()
		}(ii, tt)
	}
	wg.Wait()
}

func TestIssue3(t *testing.T) {
	// https://github.com/microcosm-cc/bluemonday/issues/3

	p := UGCPolicy()
	p.AllowStyling()

	tests := []test{
		{
			in:       `Hello <span class="foo bar bash">there</span> world.`,
			expected: `Hello <span class="foo bar bash">there</span> world.`,
		},
		{
			in:       `Hello <span class="javascript:alert(123)">there</span> world.`,
			expected: `Hello <span>there</span> world.`,
		},
		{
			in:       `Hello <span class="><script src="http://hackers.org/XSS.js"></script>">there</span> world.`,
			expected: `Hello <span>&#34;&gt;there</span> world.`,
		},
		{
			in:       `Hello <span class="><script src='http://hackers.org/XSS.js'></script>">there</span> world.`,
			expected: `Hello <span>there</span> world.`,
		},
	}

	wg := sync.WaitGroup{}
	wg.Add(len(tests))
	for ii, tt := range tests {
		go func(ii int, tt test) {
			out := p.Sanitize(tt.in)
			if out != tt.expected {
				t.Errorf(
					"test %d failed;\ninput   : %s\noutput  : %s\nexpected: %s",
					ii,
					tt.in,
					out,
					tt.expected,
				)
			}
			wg.Done()
		}(ii, tt)
	}
	wg.Wait()
}

func TestIssue9(t *testing.T) {
	p := UGCPolicy()
	p.AllowAttrs("class").Matching(SpaceSeparatedTokens).OnElements("div", "span")
	p.AllowAttrs("class", "name").Matching(SpaceSeparatedTokens).OnElements("a")
	p.AllowAttrs("rel").Matching(regexp.MustCompile(`^nofollow$`)).OnElements("a")
	p.AllowAttrs("aria-hidden").Matching(regexp.MustCompile(`^true$`)).OnElements("a")
	p.AllowDataURIImages()

	tt := test{
		in:       `<h2><a name="git-diff" class="anchor" href="#git-diff" rel="nofollow" aria-hidden="true"><span class="octicon octicon-link"></span></a>git diff</h2>`,
		expected: `<h2><a name="git-diff" class="anchor" href="#git-diff" rel="nofollow" aria-hidden="true"><span class="octicon octicon-link"></span></a>git diff</h2>`,
	}
	out := p.Sanitize(tt.in)
	if out != tt.expected {
		t.Errorf(
			"test failed;\ninput   : %s\noutput  : %s\nexpected: %s",
			tt.in,
			out,
			tt.expected,
		)
	}

	tt = test{
		in:       `<h2><a name="git-diff" class="anchor" href="#git-diff" aria-hidden="true"><span class="octicon octicon-link"></span></a>git diff</h2>`,
		expected: `<h2><a name="git-diff" class="anchor" href="#git-diff" aria-hidden="true" rel="nofollow"><span class="octicon octicon-link"></span></a>git diff</h2>`,
	}
	out = p.Sanitize(tt.in)
	if out != tt.expected {
		t.Errorf(
			"test failed;\ninput   : %s\noutput  : %s\nexpected: %s",
			tt.in,
			out,
			tt.expected,
		)
	}

	p.AddTargetBlankToFullyQualifiedLinks(true)

	tt = test{
		in:       `<h2><a name="git-diff" class="anchor" href="#git-diff" aria-hidden="true"><span class="octicon octicon-link"></span></a>git diff</h2>`,
		expected: `<h2><a name="git-diff" class="anchor" href="#git-diff" aria-hidden="true" rel="nofollow"><span class="octicon octicon-link"></span></a>git diff</h2>`,
	}
	out = p.Sanitize(tt.in)
	if out != tt.expected {
		t.Errorf(
			"test failed;\ninput   : %s\noutput  : %s\nexpected: %s",
			tt.in,
			out,
			tt.expected,
		)
	}

	tt = test{
		in:       `<h2><a name="git-diff" class="anchor" href="https://github.com/shurcooL/github_flavored_markdown/blob/master/sanitize_test.go" aria-hidden="true"><span class="octicon octicon-link"></span></a>git diff</h2>`,
		expected: `<h2><a name="git-diff" class="anchor" href="https://github.com/shurcooL/github_flavored_markdown/blob/master/sanitize_test.go" aria-hidden="true" target="_blank" rel="nofollow noopener"><span class="octicon octicon-link"></span></a>git diff</h2>`,
	}
	out = p.Sanitize(tt.in)
	if out != tt.expected {
		t.Errorf(
			"test failed;\ninput   : %s\noutput  : %s\nexpected: %s",
			tt.in,
			out,
			tt.expected,
		)
	}

	tt = test{
		in:       `<h2><a name="git-diff" class="anchor" href="https://github.com/shurcooL/github_flavored_markdown/blob/master/sanitize_test.go" aria-hidden="true" target="namedwindow"><span class="octicon octicon-link"></span></a>git diff</h2>`,
		expected: `<h2><a name="git-diff" class="anchor" href="https://github.com/shurcooL/github_flavored_markdown/blob/master/sanitize_test.go" aria-hidden="true" target="_blank" rel="nofollow noopener"><span class="octicon octicon-link"></span></a>git diff</h2>`,
	}
	out = p.Sanitize(tt.in)
	if out != tt.expected {
		t.Errorf(
			"test failed;\ninput   : %s\noutput  : %s\nexpected: %s",
			tt.in,
			out,
			tt.expected,
		)
	}
}

func TestIssue18(t *testing.T) {
	p := UGCPolicy()

	p.AllowAttrs("color").OnElements("font")
	p.AllowElements("font")

	tt := test{
		in:       `<font face="Arial">No link here. <a href="http://link.com">link here</a>.</font> Should not be linked here.`,
		expected: `No link here. <a href="http://link.com" rel="nofollow">link here</a>. Should not be linked here.`,
	}
	out := p.Sanitize(tt.in)
	if out != tt.expected {
		t.Errorf(
			"test failed;\ninput   : %s\noutput  : %s\nexpected: %s",
			tt.in,
			out,
			tt.expected)
	}
}

func TestIssue23(t *testing.T) {
	p := NewPolicy()
	p.SkipElementsContent("tag1", "tag2")
	input := `<tag1>cut<tag2></tag2>harm</tag1><tag1>123</tag1><tag2>234</tag2>`
	out := p.Sanitize(input)
	expected := ""
	if out != expected {
		t.Errorf(
			"test failed;\ninput   : %s\noutput  : %s\nexpected: %s",
			input,
			out,
			expected)
	}

	p = NewPolicy()
	p.SkipElementsContent("tag")
	p.AllowElements("p")
	input = `<tag>234<p>asd</p></tag>`
	out = p.Sanitize(input)
	expected = ""
	if out != expected {
		t.Errorf(
			"test failed;\ninput   : %s\noutput  : %s\nexpected: %s",
			input,
			out,
			expected)
	}

	p = NewPolicy()
	p.SkipElementsContent("tag")
	p.AllowElements("p", "br")
	input = `<tag>234<p>as<br/>d</p></tag>`
	out = p.Sanitize(input)
	expected = ""
	if out != expected {
		t.Errorf(
			"test failed;\ninput   : %s\noutput  : %s\nexpected: %s",
			input,
			out,
			expected)
	}
}

func TestIssue51(t *testing.T) {
	// Whitespace in URLs is permitted within HTML according to:
	// https://dev.w3.org/html5/spec-LC/urls.html#parsing-urls
	//
	// We were aggressively rejecting URLs that contained line feeds but these
	// are permitted.
	//
	// This test ensures that we do not regress that fix.
	p := NewPolicy()
	p.AllowImages()
	p.AllowDataURIImages()

	input := `<img src="data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAEgAAABICAIAAADajyQQAAAAhnpUWHRSYXcgcHJvZmlsZSB0eXBlIGV4aWYAAHjadY5LCsNADEP3c4oewb+R7eOUkEBv0OPXZpKmm76FLIQRGvv7dYxHwyTDpgcSoMLSUp5lghZKxELct3RxXuVycsdDZRlkONn9aGd+MRWBw80dExs2qXbZlTVKu6hbqWfkT8l30Z/8WvEBQsUsKBcOhtYAAAoCaVRYdFhNTDpjb20uYWRvYmUueG1wAAAAAAA8P3hwYWNrZXQgYmVnaW49Iu+7vyIgaWQ9Ilc1TTBNcENlaGlIenJlU3pOVGN6a2M5ZCI/Pgo8eDp4bXBtZXRhIHhtbG5zOng9ImFkb2JlOm5zOm1ldGEvIiB4OnhtcHRrPSJYTVAgQ29yZSA0LjQuMC1FeGl2MiI+CiA8cmRmOlJERiB4bWxuczpyZGY9Imh0dHA6Ly93d3cudzMub3JnLzE5OTkvMDIvMjItcmRmLXN5bnRheC1ucyMiPgogIDxyZGY6RGVzY3JpcHRpb24gcmRmOmFib3V0PSIiCiAgICB4bWxuczpleGlmPSJodHRwOi8vbnMuYWRvYmUuY29tL2V4aWYvMS4wLyIKICAgIHhtbG5zOnRpZmY9Imh0dHA6Ly9ucy5hZG9iZS5jb20vdGlmZi8xLjAvIgogICBleGlmOlBpeGVsWERpbWVuc2lvbj0iNzIiCiAgIGV4aWY6UGl4ZWxZRGltZW5zaW9uPSI3MiIKICAgdGlmZjpJbWFnZVdpZHRoPSI3MiIKICAgdGlmZjpJbWFnZUhlaWdodD0iNzIiCiAgIHRpZmY6T3JpZW50YXRpb249IjEiLz4KIDwvcmRmOlJERj4KPC94OnhtcG1ldGE+CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIAogICAgICAgICAgICAgICAgICAgICAgICAgICAKPD94cGFja2V0IGVuZD0idyI/Pq6cYi8AAAADc0JJVAgICNvhT+AAAAN7SURBVGje7dtRSBNhHADwfxJ3L96Le0kf1GD1sBDyO5ALbEkyMyY9bHswg+FDW5B7EKVhJSeElrQUcRIkFFHoi0toPriEVi8KbUQxKSYNk8HpYE5ot4e7e/l68NT08aTp6v9/25+P7+O3/3d3H3ffB7RooSSH7IQQYu0KS4qeeeEWyHbY+qLZvbbZiEcghBBHIJ43NhrQ4oYiRUU7sQ0lFJqPizbBEViUFCWfnOmyCp4ZaV/bfHLKIwiecLYUYJTSbLid2ALJX/E+q7VnUdGz0pSDOKakA39DQrQSd8RI0cqgCLEe8rZ55zb1X5oKwLAMywJoANpOI4ZhAEBdHnA6B5ZVPalqwHCckTGLAqvi69jPwZF36yrIK6GR4NrZjrbTbK2ziVsaeba0CaD+nAtOrtU6m6rY2qbazYWH08syqOtLwUcfoamjzpCsSPNPigy5bYQQIti7xuP6VaOshsV26052Uc/mE1M9DoEQQmxuMbyqGBvwBKUU/sUog380EIYwhCEMYQhD2DGMk4VCASuGMIQhDGEIQ9hxe0Af5eDyj7ejw5PRVAGgwnLNJ/qaK+HTnRZ/bF8rc9/s86umEoKpXyb8E+nWx7NP65nM+9HuB/5T5tc3zouzs/q7Ri0d6vdHLb5GU2lNxa0txuLq6aw3scDVNHZcrsjE0jKwnEmPQnQiVLg26KvnSmwqVjb3DjXvVC8djRVOtVbvGTbmh19utY55z7Cle/NQN94/8IcYl+iq2U19m55Mmb2d51ijnR45TP7yrPvmaME1NnZrrzjy1+mo1tBp6OI6DndF2Ji/f3s03Si+6r34p0FNRb5q50ULd4iuj7Bi8reR7uFUgzjYYYFcLpfL5WT9I0sm9l2rbjQfxnWEFcvFJsIZgEi/O3LgiaVmUluMubr8UN2fkGUZl1QIQxjCEIYwhCEMYYdbUuE+D4QhDGEIQxjC/luYvBK667zE8zx/oc0XXNK3B8vL0716tsX75IOe3fzwxNtyged5vuX6QGhFNThkUfakJ0Sb4H6RyFOqrIZ7rIInmqdUSQbsxDEez+5mI3lKpRm3YOuLSAql2fi4g9gDSUObZ4vy+o2tu/dmATiOBZA1UIEzcQDAMiaO+aPV9nbtKtfkwhWW4wBUWVOh3FTFsce2YnhSAk9K4EmJvxt4UgJPSuCSCmEIQxjCEAYAAL8BrebxGP8KiJcAAAAASUVORK5CYII=" alt="">`
	out := p.Sanitize(input)
	expected := `<img src="data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAEgAAABICAIAAADajyQQAAAAhnpUWHRSYXcgcHJvZmlsZSB0eXBlIGV4aWYAAHjadY5LCsNADEP3c4oewb+R7eOUkEBv0OPXZpKmm76FLIQRGvv7dYxHwyTDpgcSoMLSUp5lghZKxELct3RxXuVycsdDZRlkONn9aGd+MRWBw80dExs2qXbZlTVKu6hbqWfkT8l30Z/8WvEBQsUsKBcOhtYAAAoCaVRYdFhNTDpjb20uYWRvYmUueG1wAAAAAAA8P3hwYWNrZXQgYmVnaW49Iu+7vyIgaWQ9Ilc1TTBNcENlaGlIenJlU3pOVGN6a2M5ZCI/Pgo8eDp4bXBtZXRhIHhtbG5zOng9ImFkb2JlOm5zOm1ldGEvIiB4OnhtcHRrPSJYTVAgQ29yZSA0LjQuMC1FeGl2MiI+CiA8cmRmOlJERiB4bWxuczpyZGY9Imh0dHA6Ly93d3cudzMub3JnLzE5OTkvMDIvMjItcmRmLXN5bnRheC1ucyMiPgogIDxyZGY6RGVzY3JpcHRpb24gcmRmOmFib3V0PSIiCiAgICB4bWxuczpleGlmPSJodHRwOi8vbnMuYWRvYmUuY29tL2V4aWYvMS4wLyIKICAgIHhtbG5zOnRpZmY9Imh0dHA6Ly9ucy5hZG9iZS5jb20vdGlmZi8xLjAvIgogICBleGlmOlBpeGVsWERpbWVuc2lvbj0iNzIiCiAgIGV4aWY6UGl4ZWxZRGltZW5zaW9uPSI3MiIKICAgdGlmZjpJbWFnZVdpZHRoPSI3MiIKICAgdGlmZjpJbWFnZUhlaWdodD0iNzIiCiAgIHRpZmY6T3JpZW50YXRpb249IjEiLz4KIDwvcmRmOlJERj4KPC94OnhtcG1ldGE+CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIAogICAgICAgICAgICAgICAgICAgICAgICAgICAKPD94cGFja2V0IGVuZD0idyI/Pq6cYi8AAAADc0JJVAgICNvhT+AAAAN7SURBVGje7dtRSBNhHADwfxJ3L96Le0kf1GD1sBDyO5ALbEkyMyY9bHswg+FDW5B7EKVhJSeElrQUcRIkFFHoi0toPriEVi8KbUQxKSYNk8HpYE5ot4e7e/l68NT08aTp6v9/25+P7+O3/3d3H3ffB7RooSSH7IQQYu0KS4qeeeEWyHbY+qLZvbbZiEcghBBHIJ43NhrQ4oYiRUU7sQ0lFJqPizbBEViUFCWfnOmyCp4ZaV/bfHLKIwiecLYUYJTSbLid2ALJX/E+q7VnUdGz0pSDOKakA39DQrQSd8RI0cqgCLEe8rZ55zb1X5oKwLAMywJoANpOI4ZhAEBdHnA6B5ZVPalqwHCckTGLAqvi69jPwZF36yrIK6GR4NrZjrbTbK2ziVsaeba0CaD+nAtOrtU6m6rY2qbazYWH08syqOtLwUcfoamjzpCsSPNPigy5bYQQIti7xuP6VaOshsV26052Uc/mE1M9DoEQQmxuMbyqGBvwBKUU/sUog380EIYwhCEMYQhD2DGMk4VCASuGMIQhDGEIQ9hxe0Af5eDyj7ejw5PRVAGgwnLNJ/qaK+HTnRZ/bF8rc9/s86umEoKpXyb8E+nWx7NP65nM+9HuB/5T5tc3zouzs/q7Ri0d6vdHLb5GU2lNxa0txuLq6aw3scDVNHZcrsjE0jKwnEmPQnQiVLg26KvnSmwqVjb3DjXvVC8djRVOtVbvGTbmh19utY55z7Cle/NQN94/8IcYl+iq2U19m55Mmb2d51ijnR45TP7yrPvmaME1NnZrrzjy1+mo1tBp6OI6DndF2Ji/f3s03Si+6r34p0FNRb5q50ULd4iuj7Bi8reR7uFUgzjYYYFcLpfL5WT9I0sm9l2rbjQfxnWEFcvFJsIZgEi/O3LgiaVmUluMubr8UN2fkGUZl1QIQxjCEIYwhCEMYYdbUuE+D4QhDGEIQxjC/luYvBK667zE8zx/oc0XXNK3B8vL0716tsX75IOe3fzwxNtyged5vuX6QGhFNThkUfakJ0Sb4H6RyFOqrIZ7rIInmqdUSQbsxDEez+5mI3lKpRm3YOuLSAql2fi4g9gDSUObZ4vy+o2tu/dmATiOBZA1UIEzcQDAMiaO+aPV9nbtKtfkwhWW4wBUWVOh3FTFsce2YnhSAk9K4EmJvxt4UgJPSuCSCmEIQxjCEAYAAL8BrebxGP8KiJcAAAAASUVORK5CYII=" alt="">`
	if out != expected {
		t.Errorf(
			"test failed;\ninput   : %s\noutput  : %s\nexpected: %s",
			input,
			out,
			expected)
	}

	input = `<img src="data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAEgAAABICAIAAADajyQQAAAAhnpUWHRSYXcgcHJvZmlsZSB0
eXBlIGV4aWYAAHjadY5LCsNADEP3c4oewb+R7eOUkEBv0OPXZpKmm76FLIQRGvv7dYxHwyTD
pgcSoMLSUp5lghZKxELct3RxXuVycsdDZRlkONn9aGd+MRWBw80dExs2qXbZlTVKu6hbqWfk
T8l30Z/8WvEBQsUsKBcOhtYAAAoCaVRYdFhNTDpjb20uYWRvYmUueG1wAAAAAAA8P3hwYWNr
ZXQgYmVnaW49Iu+7vyIgaWQ9Ilc1TTBNcENlaGlIenJlU3pOVGN6a2M5ZCI/Pgo8eDp4bXBt
ZXRhIHhtbG5zOng9ImFkb2JlOm5zOm1ldGEvIiB4OnhtcHRrPSJYTVAgQ29yZSA0LjQuMC1F
eGl2MiI+CiA8cmRmOlJERiB4bWxuczpyZGY9Imh0dHA6Ly93d3cudzMub3JnLzE5OTkvMDIv
MjItcmRmLXN5bnRheC1ucyMiPgogIDxyZGY6RGVzY3JpcHRpb24gcmRmOmFib3V0PSIiCiAg
ICB4bWxuczpleGlmPSJodHRwOi8vbnMuYWRvYmUuY29tL2V4aWYvMS4wLyIKICAgIHhtbG5z
OnRpZmY9Imh0dHA6Ly9ucy5hZG9iZS5jb20vdGlmZi8xLjAvIgogICBleGlmOlBpeGVsWERp
bWVuc2lvbj0iNzIiCiAgIGV4aWY6UGl4ZWxZRGltZW5zaW9uPSI3MiIKICAgdGlmZjpJbWFn
ZVdpZHRoPSI3MiIKICAgdGlmZjpJbWFnZUhlaWdodD0iNzIiCiAgIHRpZmY6T3JpZW50YXRp
b249IjEiLz4KIDwvcmRmOlJERj4KPC94OnhtcG1ldGE+CiAgICAgICAgICAgICAgICAgICAg
ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg
ICAgICAgICAgICAgICAgICAgICAgICAgICAKICAgICAgICAgICAgICAgICAgICAgICAgICAg
ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg
ICAgICAgICAgICAgICAgICAgIAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg
ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg
ICAgICAgICAgICAgCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg
ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg
ICAgICAKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg
ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIAog
ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg
ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgCiAgICAgICAg
ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg
ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAKICAgICAgICAgICAgICAg
ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg
ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIAogICAgICAgICAgICAgICAgICAgICAg
ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg
ICAgICAgICAgICAgICAgICAgICAgICAgCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAg
ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg
ICAgICAgICAgICAgICAgICAKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg
ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg
ICAgICAgICAgIAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg
ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg
ICAgCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg
ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAKICAg
ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg
ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIAogICAgICAgICAg
ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg
ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgCiAgICAgICAgICAgICAgICAg
ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg
ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAKICAgICAgICAgICAgICAgICAgICAgICAg
ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg
ICAgICAgICAgICAgICAgICAgICAgIAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg
ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg
ICAgICAgICAgICAgICAgCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg
ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg
ICAgICAgICAKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg
ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg
IAogICAgICAgICAgICAgICAgICAgICAgICAgICAKPD94cGFja2V0IGVuZD0idyI/Pq6cYi8A
AAADc0JJVAgICNvhT+AAAAN7SURBVGje7dtRSBNhHADwfxJ3L96Le0kf1GD1sBDyO5ALbEky
MyY9bHswg+FDW5B7EKVhJSeElrQUcRIkFFHoi0toPriEVi8KbUQxKSYNk8HpYE5ot4e7e/l6
8NT08aTp6v9/25+P7+O3/3d3H3ffB7RooSSH7IQQYu0KS4qeeeEWyHbY+qLZvbbZiEcghBBH
IJ43NhrQ4oYiRUU7sQ0lFJqPizbBEViUFCWfnOmyCp4ZaV/bfHLKIwiecLYUYJTSbLid2ALJ
X/E+q7VnUdGz0pSDOKakA39DQrQSd8RI0cqgCLEe8rZ55zb1X5oKwLAMywJoANpOI4ZhAEBd
HnA6B5ZVPalqwHCckTGLAqvi69jPwZF36yrIK6GR4NrZjrbTbK2ziVsaeba0CaD+nAtOrtU6
m6rY2qbazYWH08syqOtLwUcfoamjzpCsSPNPigy5bYQQIti7xuP6VaOshsV26052Uc/mE1M9
DoEQQmxuMbyqGBvwBKUU/sUog380EIYwhCEMYQhD2DGMk4VCASuGMIQhDGEIQ9hxe0Af5eDy
j7ejw5PRVAGgwnLNJ/qaK+HTnRZ/bF8rc9/s86umEoKpXyb8E+nWx7NP65nM+9HuB/5T5tc3
zouzs/q7Ri0d6vdHLb5GU2lNxa0txuLq6aw3scDVNHZcrsjE0jKwnEmPQnQiVLg26KvnSmwq
Vjb3DjXvVC8djRVOtVbvGTbmh19utY55z7Cle/NQN94/8IcYl+iq2U19m55Mmb2d51ijnR45
TP7yrPvmaME1NnZrrzjy1+mo1tBp6OI6DndF2Ji/f3s03Si+6r34p0FNRb5q50ULd4iuj7Bi
8reR7uFUgzjYYYFcLpfL5WT9I0sm9l2rbjQfxnWEFcvFJsIZgEi/O3LgiaVmUluMubr8UN2f
kGUZl1QIQxjCEIYwhCEMYYdbUuE+D4QhDGEIQxjC/luYvBK667zE8zx/oc0XXNK3B8vL0716
tsX75IOe3fzwxNtyged5vuX6QGhFNThkUfakJ0Sb4H6RyFOqrIZ7rIInmqdUSQbsxDEez+5m
I3lKpRm3YOuLSAql2fi4g9gDSUObZ4vy+o2tu/dmATiOBZA1UIEzcQDAMiaO+aPV9nbtKtfk
whWW4wBUWVOh3FTFsce2YnhSAk9K4EmJvxt4UgJPSuCSCmEIQxjCEAYAAL8BrebxGP8KiJcA
AAAASUVORK5CYII=" alt="">`
	out = p.Sanitize(input)
	expected = `<img src="data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAEgAAABICAIAAADajyQQAAAAhnpUWHRSYXcgcHJvZmlsZSB0eXBlIGV4aWYAAHjadY5LCsNADEP3c4oewb+R7eOUkEBv0OPXZpKmm76FLIQRGvv7dYxHwyTDpgcSoMLSUp5lghZKxELct3RxXuVycsdDZRlkONn9aGd+MRWBw80dExs2qXbZlTVKu6hbqWfkT8l30Z/8WvEBQsUsKBcOhtYAAAoCaVRYdFhNTDpjb20uYWRvYmUueG1wAAAAAAA8P3hwYWNrZXQgYmVnaW49Iu+7vyIgaWQ9Ilc1TTBNcENlaGlIenJlU3pOVGN6a2M5ZCI/Pgo8eDp4bXBtZXRhIHhtbG5zOng9ImFkb2JlOm5zOm1ldGEvIiB4OnhtcHRrPSJYTVAgQ29yZSA0LjQuMC1FeGl2MiI+CiA8cmRmOlJERiB4bWxuczpyZGY9Imh0dHA6Ly93d3cudzMub3JnLzE5OTkvMDIvMjItcmRmLXN5bnRheC1ucyMiPgogIDxyZGY6RGVzY3JpcHRpb24gcmRmOmFib3V0PSIiCiAgICB4bWxuczpleGlmPSJodHRwOi8vbnMuYWRvYmUuY29tL2V4aWYvMS4wLyIKICAgIHhtbG5zOnRpZmY9Imh0dHA6Ly9ucy5hZG9iZS5jb20vdGlmZi8xLjAvIgogICBleGlmOlBpeGVsWERpbWVuc2lvbj0iNzIiCiAgIGV4aWY6UGl4ZWxZRGltZW5zaW9uPSI3MiIKICAgdGlmZjpJbWFnZVdpZHRoPSI3MiIKICAgdGlmZjpJbWFnZUhlaWdodD0iNzIiCiAgIHRpZmY6T3JpZW50YXRpb249IjEiLz4KIDwvcmRmOlJERj4KPC94OnhtcG1ldGE+CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIAogICAgICAgICAgICAgICAgICAgICAgICAgICAKPD94cGFja2V0IGVuZD0idyI/Pq6cYi8AAAADc0JJVAgICNvhT+AAAAN7SURBVGje7dtRSBNhHADwfxJ3L96Le0kf1GD1sBDyO5ALbEkyMyY9bHswg+FDW5B7EKVhJSeElrQUcRIkFFHoi0toPriEVi8KbUQxKSYNk8HpYE5ot4e7e/l68NT08aTp6v9/25+P7+O3/3d3H3ffB7RooSSH7IQQYu0KS4qeeeEWyHbY+qLZvbbZiEcghBBHIJ43NhrQ4oYiRUU7sQ0lFJqPizbBEViUFCWfnOmyCp4ZaV/bfHLKIwiecLYUYJTSbLid2ALJX/E+q7VnUdGz0pSDOKakA39DQrQSd8RI0cqgCLEe8rZ55zb1X5oKwLAMywJoANpOI4ZhAEBdHnA6B5ZVPalqwHCckTGLAqvi69jPwZF36yrIK6GR4NrZjrbTbK2ziVsaeba0CaD+nAtOrtU6m6rY2qbazYWH08syqOtLwUcfoamjzpCsSPNPigy5bYQQIti7xuP6VaOshsV26052Uc/mE1M9DoEQQmxuMbyqGBvwBKUU/sUog380EIYwhCEMYQhD2DGMk4VCASuGMIQhDGEIQ9hxe0Af5eDyj7ejw5PRVAGgwnLNJ/qaK+HTnRZ/bF8rc9/s86umEoKpXyb8E+nWx7NP65nM+9HuB/5T5tc3zouzs/q7Ri0d6vdHLb5GU2lNxa0txuLq6aw3scDVNHZcrsjE0jKwnEmPQnQiVLg26KvnSmwqVjb3DjXvVC8djRVOtVbvGTbmh19utY55z7Cle/NQN94/8IcYl+iq2U19m55Mmb2d51ijnR45TP7yrPvmaME1NnZrrzjy1+mo1tBp6OI6DndF2Ji/f3s03Si+6r34p0FNRb5q50ULd4iuj7Bi8reR7uFUgzjYYYFcLpfL5WT9I0sm9l2rbjQfxnWEFcvFJsIZgEi/O3LgiaVmUluMubr8UN2fkGUZl1QIQxjCEIYwhCEMYYdbUuE+D4QhDGEIQxjC/luYvBK667zE8zx/oc0XXNK3B8vL0716tsX75IOe3fzwxNtyged5vuX6QGhFNThkUfakJ0Sb4H6RyFOqrIZ7rIInmqdUSQbsxDEez+5mI3lKpRm3YOuLSAql2fi4g9gDSUObZ4vy+o2tu/dmATiOBZA1UIEzcQDAMiaO+aPV9nbtKtfkwhWW4wBUWVOh3FTFsce2YnhSAk9K4EmJvxt4UgJPSuCSCmEIQxjCEAYAAL8BrebxGP8KiJcAAAAASUVORK5CYII=" alt="">`
	if out != expected {
		t.Errorf(
			"test failed;\ninput   : %s\noutput  : %s\nexpected: %s",
			input,
			out,
			expected)
	}
}

func TestIssue55(t *testing.T) {
	p1 := NewPolicy()
	p2 := UGCPolicy()
	p3 := UGCPolicy().AllowElements("script").AllowUnsafe(true)

	in := `<SCRIPT>document.write('<h1><header/h1>')</SCRIPT>`
	assert.Empty(t, p1.Sanitize(in))
	assert.Empty(t, p2.Sanitize(in))

	assert.Equal(t, `<script>document.write('<h1><header/h1>')</script>`,
		p3.Sanitize(in))
}

func TestIssue85(t *testing.T) {
	p := UGCPolicy()
	p.AllowAttrs("rel").OnElements("a")
	p.RequireNoReferrerOnLinks(true)
	p.AddTargetBlankToFullyQualifiedLinks(true)
	p.AllowAttrs("target").Matching(Paragraph).OnElements("a")

	tests := []test{
		{
			in:       `<a href="/path" />`,
			expected: `<a href="/path" rel="nofollow noreferrer"/>`,
		},
		{
			in:       `<a href="/path" target="_blank" />`,
			expected: `<a href="/path" target="_blank" rel="nofollow noreferrer noopener"/>`,
		},
		{
			in:       `<a href="/path" target="foo" />`,
			expected: `<a href="/path" target="foo" rel="nofollow noreferrer"/>`,
		},
		{
			in:       `<a href="https://www.google.com/" />`,
			expected: `<a href="https://www.google.com/" target="_blank" rel="nofollow noreferrer noopener"/>`,
		},
		{
			in:       `<a href="https://www.google.com/" target="_blank"/>`,
			expected: `<a href="https://www.google.com/" target="_blank" rel="nofollow noreferrer noopener"/>`,
		},
		{
			in:       `<a href="https://www.google.com/" rel="nofollow"/>`,
			expected: `<a href="https://www.google.com/" rel="nofollow noreferrer noopener" target="_blank"/>`,
		},
		{
			in:       `<a href="https://www.google.com/" rel="noopener"/>`,
			expected: `<a href="https://www.google.com/" rel="noopener nofollow noreferrer" target="_blank"/>`,
		},
		{
			in:       `<a href="https://www.google.com/" rel="noopener nofollow" />`,
			expected: `<a href="https://www.google.com/" rel="noopener nofollow noreferrer" target="_blank"/>`,
		},
		{
			in:       `<a href="https://www.google.com/" target="foo" />`,
			expected: `<a href="https://www.google.com/" target="_blank" rel="nofollow noreferrer noopener"/>`,
		},
		{
			in:       `<a href="https://www.google.com/" rel="external"/>`,
			expected: `<a href="https://www.google.com/" rel="external nofollow noreferrer noopener" target="_blank"/>`,
		},
	}

	// These tests are run concurrently to enable the race detector to pick up
	// potential issues
	wg := sync.WaitGroup{}
	wg.Add(len(tests))
	for ii, tt := range tests {
		go func(ii int, tt test) {
			out := p.Sanitize(tt.in)
			if out != tt.expected {
				t.Errorf(
					"test %d failed;\ninput   : %s\noutput  : %s\nexpected: %s",
					ii,
					tt.in,
					out,
					tt.expected,
				)
			}
			wg.Done()
		}(ii, tt)
	}
	wg.Wait()
}

func TestIssue107(t *testing.T) {
	p := UGCPolicy()
	p.RequireCrossOriginAnonymous(true)

	p1 := UGCPolicy()
	p1.RequireCrossOriginAnonymous(true)
	p1.AllowAttrs("crossorigin").Globally()

	tests := []test{
		{
			in:       `<img src="/path" />`,
			expected: `<img src="/path" crossorigin="anonymous"/>`,
		},
		{
			in:       `<img src="/path" crossorigin="use-credentials"/>`,
			expected: `<img src="/path" crossorigin="anonymous"/>`,
		},
		{
			in:       `<img src="/path" crossorigin=""/>`,
			expected: `<img src="/path" crossorigin="anonymous"/>`,
		},
	}

	// These tests are run concurrently to enable the race detector to pick up
	// potential issues
	wg := sync.WaitGroup{}
	wg.Add(len(tests))
	for ii, tt := range tests {
		go func(ii int, tt test) {
			out := p.Sanitize(tt.in)
			if out != tt.expected {
				t.Errorf(
					"test %d failed;\ninput   : %s\noutput  : %s\nexpected: %s",
					ii,
					tt.in,
					out,
					tt.expected,
				)
			}
			out = p1.Sanitize(tt.in)
			if out != tt.expected {
				t.Errorf(
					"test %d failed with policy p1;\ninput   : %s\noutput  : %s\nexpected: %s",
					ii,
					tt.in,
					out,
					tt.expected,
				)
			}
			wg.Done()
		}(ii, tt)
	}
	wg.Wait()
}

func TestIssue134(t *testing.T) {
	// Do all the methods work?
	//
	// Are all the times roughly consistent?
	in := `<p style="width:100%;height:100%;background-image: url('data:image/svg+xml;base64,PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0idXRmLTgiPz4KPCFET0NUWVBFIHN2ZyBQVUJMSUMgIi0vL1czQy8vRFREIFNWRyAxLjEvL0VOIiAiaHR0cDovL3d3dy53My5vcmcvR3JhcGhpY3MvU1ZHLzEuMS9EVEQvc3ZnMTEuZHRkIj4KPHN2ZyB2ZXJzaW9uPSIxLjEiIHhtbG5zPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwL3N2ZyIgCiAgICAgICAgICAgICAgICAgICB4bWxuczp4bGluaz0iaHR0cDovL3d3dy53My5vcmcvMTk5OS94bGluayIgCiAgICAgICAgICAgICAgICAgICB2aWV3Qm94PSIwIDAgNjk2IDI1OCIgCiAgICAgICAgICAgICAgICAgICBwcmVzZXJ2ZUFzcGVjdFJhdGlvPSJ4TWlkWU1pZCBtZWV0Ij4KPGc+Cgk8cGF0aCBmaWxsPSIjQURFMEU0IiBkPSJNMC43ODcsNTMuODI1aDQxLjY2OXYxMTMuODM4aDcyLjgxNHYzNi41MTFIMC43ODdWNTMuODI1eiIvPgoJPHBhdGggZmlsbD0iI0FERTBFNCIgZD0iTTEzMy4xMDUsNTMuODI1aDEyMC4yNzV2MzYuNTE0aC03OC42MXYyNS41Nmg3MS4wOTN2MzQuNTgyaC03MS4wOTN2NTMuNjk0aC00MS42NjVWNTMuODI1eiIvPgoJPHBhdGggZmlsbD0iI0FERTBFNCIgZD0iTTI2Ny4xMzQsMTI5LjQyOXYtMC40MjdjMC00My44MTYsMzQuMzY0LTc4LjE4Miw4MC45NzQtNzguMTgyYzI2LjQyMSwwLDQ1LjEwNyw4LjE2MSw2MSwyMS45MDgKCQlsLTI0LjQ4NiwyOS40MjNjLTEwLjc0LTkuMDE5LTIxLjQ3OS0xNC4xNzItMzYuMjk0LTE0LjE3MmMtMjEuNjk1LDAtMzguNDUyLDE4LjI1NC0zOC40NTIsNDEuMjM5djAuNDI1CgkJYzAsMjQuMjczLDE2Ljk2Niw0MS42NzIsNDAuODA0LDQxLjY3MmMxMC4xMDMsMCwxNy44MzYtMi4xNDYsMjQuMDYzLTYuMjMxdi0xOC4yNTdoLTI5LjY0M3YtMzAuNWg2OS4xNTl2NjcuNjU5CgkJYy0xNS44OTMsMTMuMTA0LTM4LjAxNiwyMy4xOTctNjUuMjkxLDIzLjE5N0MzMDIuMTQ3LDIwNy4xODIsMjY3LjEzNCwxNzQuOTY0LDI2Ny4xMzQsMTI5LjQyOXoiLz4KCTxwYXRoIGZpbGw9IiNBREUwRTQiIGQ9Ik00MjYuMDg3LDE4MS44MzdsMjMuMTk1LTI3LjcwOWMxNC44MjIsMTEuODE2LDMxLjM2MSwxOC4wNDEsNDguNzU1LDE4LjA0MQoJCWMxMS4xNzEsMCwxNy4xODYtMy44NjYsMTcuMTg2LTEwLjMwNnYtMC40MzdjMC02LjIyNS00Ljk0LTkuNjY1LTI1LjM0Ny0xNC4zODdjLTMyLjAwNi03LjMwMi01Ni43MDItMTYuMzIxLTU2LjcwMi00Ny4yNXYtMC40MwoJCWMwLTI3LjkyMiwyMi4xMjMtNDguMTEzLDU4LjItNDguMTEzYzI1LjU2NCwwLDQ1LjU0Miw2Ljg3NSw2MS44NTgsMTkuOTczbC0yMC44MjksMjkuNDI5CgkJYy0xMy43NDctOS42NjgtMjguNzc4LTE0LjgxOC00Mi4wOTYtMTQuODE4Yy0xMC4wOTcsMC0xNS4wMzcsNC4yOTQtMTUuMDM3LDkuNjYzdjAuNDNjMCw2Ljg2OSw1LjE1NSw5Ljg4MSwyNS45OTIsMTQuNjA2CgkJYzM0LjU3OSw3LjUxNiw1Ni4wNTcsMTguNjg3LDU2LjA1Nyw0Ni44MTl2MC40MjdjMCwzMC43MTUtMjQuMjcxLDQ4Ljk2OS02MC43ODQsNDguOTY5CgkJQzQ2OS45MDEsMjA2Ljc0NCw0NDQuNTU3LDE5OC4zNzIsNDI2LjA4NywxODEuODM3eiIvPgoJPHBhdGggZmlsbD0iI0FERTBFNCIgZD0iTTU2My45ODQsMTgxLjgzN2wyMy4xOTEtMjcuNzA5YzE0LjgyNCwxMS44MTYsMzEuMzYyLDE4LjA0MSw0OC43NTUsMTguMDQxCgkJYzExLjE3NCwwLDE3LjE4OC0zLjg2NiwxNy4xODgtMTAuMzA2di0wLjQzN2MwLTYuMjI1LTQuOTQyLTkuNjY1LTI1LjM0NC0xNC4zODdjLTMyLjAwNS03LjMwMi01Ni43MDUtMTYuMzIxLTU2LjcwNS00Ny4yNXYtMC40MwoJCWMwLTI3LjkyMiwyMi4xMjMtNDguMTEzLDU4LjIwNS00OC4xMTNjMjUuNTU5LDAsNDUuNTM1LDYuODc1LDYxLjg1OSwxOS45NzNsLTIwLjgzOSwyOS40MjkKCQljLTEzLjc0LTkuNjY4LTI4Ljc3My0xNC44MTgtNDIuMDk3LTE0LjgxOGMtMTAuMDkxLDAtMTUuMDM1LDQuMjk0LTE1LjAzNSw5LjY2M3YwLjQzYzAsNi44NjksNS4xNTksOS44ODEsMjUuOTk1LDE0LjYwNgoJCWMzNC41NzksNy41MTYsNTYuMDU1LDE4LjY4Nyw1Ni4wNTUsNDYuODE5djAuNDI3YzAsMzAuNzE1LTI0LjI3LDQ4Ljk2OS02MC43ODUsNDguOTY5CgkJQzYwNy43OTgsMjA2Ljc0NCw1ODIuNDUzLDE5OC4zNzIsNTYzLjk4NCwxODEuODM3eiIvPgo8L2c+Cjwvc3ZnPgo=')"></p>`
	expected := `<p style="width:100%;height:100%;background-image: url(&#39;data:image/svg+xml;base64,PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0idXRmLTgiPz4KPCFET0NUWVBFIHN2ZyBQVUJMSUMgIi0vL1czQy8vRFREIFNWRyAxLjEvL0VOIiAiaHR0cDovL3d3dy53My5vcmcvR3JhcGhpY3MvU1ZHLzEuMS9EVEQvc3ZnMTEuZHRkIj4KPHN2ZyB2ZXJzaW9uPSIxLjEiIHhtbG5zPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwL3N2ZyIgCiAgICAgICAgICAgICAgICAgICB4bWxuczp4bGluaz0iaHR0cDovL3d3dy53My5vcmcvMTk5OS94bGluayIgCiAgICAgICAgICAgICAgICAgICB2aWV3Qm94PSIwIDAgNjk2IDI1OCIgCiAgICAgICAgICAgICAgICAgICBwcmVzZXJ2ZUFzcGVjdFJhdGlvPSJ4TWlkWU1pZCBtZWV0Ij4KPGc+Cgk8cGF0aCBmaWxsPSIjQURFMEU0IiBkPSJNMC43ODcsNTMuODI1aDQxLjY2OXYxMTMuODM4aDcyLjgxNHYzNi41MTFIMC43ODdWNTMuODI1eiIvPgoJPHBhdGggZmlsbD0iI0FERTBFNCIgZD0iTTEzMy4xMDUsNTMuODI1aDEyMC4yNzV2MzYuNTE0aC03OC42MXYyNS41Nmg3MS4wOTN2MzQuNTgyaC03MS4wOTN2NTMuNjk0aC00MS42NjVWNTMuODI1eiIvPgoJPHBhdGggZmlsbD0iI0FERTBFNCIgZD0iTTI2Ny4xMzQsMTI5LjQyOXYtMC40MjdjMC00My44MTYsMzQuMzY0LTc4LjE4Miw4MC45NzQtNzguMTgyYzI2LjQyMSwwLDQ1LjEwNyw4LjE2MSw2MSwyMS45MDgKCQlsLTI0LjQ4NiwyOS40MjNjLTEwLjc0LTkuMDE5LTIxLjQ3OS0xNC4xNzItMzYuMjk0LTE0LjE3MmMtMjEuNjk1LDAtMzguNDUyLDE4LjI1NC0zOC40NTIsNDEuMjM5djAuNDI1CgkJYzAsMjQuMjczLDE2Ljk2Niw0MS42NzIsNDAuODA0LDQxLjY3MmMxMC4xMDMsMCwxNy44MzYtMi4xNDYsMjQuMDYzLTYuMjMxdi0xOC4yNTdoLTI5LjY0M3YtMzAuNWg2OS4xNTl2NjcuNjU5CgkJYy0xNS44OTMsMTMuMTA0LTM4LjAxNiwyMy4xOTctNjUuMjkxLDIzLjE5N0MzMDIuMTQ3LDIwNy4xODIsMjY3LjEzNCwxNzQuOTY0LDI2Ny4xMzQsMTI5LjQyOXoiLz4KCTxwYXRoIGZpbGw9IiNBREUwRTQiIGQ9Ik00MjYuMDg3LDE4MS44MzdsMjMuMTk1LTI3LjcwOWMxNC44MjIsMTEuODE2LDMxLjM2MSwxOC4wNDEsNDguNzU1LDE4LjA0MQoJCWMxMS4xNzEsMCwxNy4xODYtMy44NjYsMTcuMTg2LTEwLjMwNnYtMC40MzdjMC02LjIyNS00Ljk0LTkuNjY1LTI1LjM0Ny0xNC4zODdjLTMyLjAwNi03LjMwMi01Ni43MDItMTYuMzIxLTU2LjcwMi00Ny4yNXYtMC40MwoJCWMwLTI3LjkyMiwyMi4xMjMtNDguMTEzLDU4LjItNDguMTEzYzI1LjU2NCwwLDQ1LjU0Miw2Ljg3NSw2MS44NTgsMTkuOTczbC0yMC44MjksMjkuNDI5CgkJYy0xMy43NDctOS42NjgtMjguNzc4LTE0LjgxOC00Mi4wOTYtMTQuODE4Yy0xMC4wOTcsMC0xNS4wMzcsNC4yOTQtMTUuMDM3LDkuNjYzdjAuNDNjMCw2Ljg2OSw1LjE1NSw5Ljg4MSwyNS45OTIsMTQuNjA2CgkJYzM0LjU3OSw3LjUxNiw1Ni4wNTcsMTguNjg3LDU2LjA1Nyw0Ni44MTl2MC40MjdjMCwzMC43MTUtMjQuMjcxLDQ4Ljk2OS02MC43ODQsNDguOTY5CgkJQzQ2OS45MDEsMjA2Ljc0NCw0NDQuNTU3LDE5OC4zNzIsNDI2LjA4NywxODEuODM3eiIvPgoJPHBhdGggZmlsbD0iI0FERTBFNCIgZD0iTTU2My45ODQsMTgxLjgzN2wyMy4xOTEtMjcuNzA5YzE0LjgyNCwxMS44MTYsMzEuMzYyLDE4LjA0MSw0OC43NTUsMTguMDQxCgkJYzExLjE3NCwwLDE3LjE4OC0zLjg2NiwxNy4xODgtMTAuMzA2di0wLjQzN2MwLTYuMjI1LTQuOTQyLTkuNjY1LTI1LjM0NC0xNC4zODdjLTMyLjAwNS03LjMwMi01Ni43MDUtMTYuMzIxLTU2LjcwNS00Ny4yNXYtMC40MwoJCWMwLTI3LjkyMiwyMi4xMjMtNDguMTEzLDU4LjIwNS00OC4xMTNjMjUuNTU5LDAsNDUuNTM1LDYuODc1LDYxLjg1OSwxOS45NzNsLTIwLjgzOSwyOS40MjkKCQljLTEzLjc0LTkuNjY4LTI4Ljc3My0xNC44MTgtNDIuMDk3LTE0LjgxOGMtMTAuMDkxLDAtMTUuMDM1LDQuMjk0LTE1LjAzNSw5LjY2M3YwLjQzYzAsNi44NjksNS4xNTksOS44ODEsMjUuOTk1LDE0LjYwNgoJCWMzNC41NzksNy41MTYsNTYuMDU1LDE4LjY4Nyw1Ni4wNTUsNDYuODE5djAuNDI3YzAsMzAuNzE1LTI0LjI3LDQ4Ljk2OS02MC43ODUsNDguOTY5CgkJQzYwNy43OTgsMjA2Ljc0NCw1ODIuNDUzLDE5OC4zNzIsNTYzLjk4NCwxODEuODM3eiIvPgo8L2c+Cjwvc3ZnPgo=&#39;)"></p>`

	p := UGCPolicy()
	p.AllowAttrs("style").OnElements("p")

	t.Run("Sanitize", func(t *testing.T) {
		out := p.Sanitize(in)
		if out != expected {
			t.Errorf(
				"test failed;\ninput   : %s\noutput  : %s\nexpected: %s",
				in,
				out,
				expected,
			)
		}
	})

	t.Run("SanitizeReader", func(t *testing.T) {
		out := p.SanitizeReader(strings.NewReader(in)).String()
		if out != expected {
			t.Errorf(
				"test failed;\ninput   : %s\noutput  : %s\nexpected: %s",
				in,
				out,
				expected,
			)
		}
	})

	t.Run("SanitizeBytes", func(t *testing.T) {
		out := string(p.SanitizeBytes([]byte(in)))
		if out != expected {
			t.Errorf(
				"test failed;\ninput   : %s\noutput  : %s\nexpected: %s",
				in,
				out,
				expected,
			)
		}
	})

	t.Run("SanitizeReaderToWriter", func(t *testing.T) {
		var buff bytes.Buffer
		var out string
		p.SanitizeReaderToWriter(strings.NewReader(in), &buff)
		out = (&buff).String()
		if out != expected {
			t.Errorf(
				"test failed;\ninput   : %s\noutput  : %s\nexpected: %s",
				in,
				out,
				expected,
			)
		}
	})
}

func TestIssue139(t *testing.T) {
	// HTML escaping of attribute values appears to occur twice
	tests := []test{
		{
			in:       `<p style="width:100%;height:100%;background-image: url('data:image/svg+xml;base64,PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0idXRmLTgiPz4KPCFET0NUWVBFIHN2ZyBQVUJMSUMgIi0vL1czQy8vRFREIFNWRyAxLjEvL0VOIiAiaHR0cDovL3d3dy53My5vcmcvR3JhcGhpY3MvU1ZHLzEuMS9EVEQvc3ZnMTEuZHRkIj4KPHN2ZyB2ZXJzaW9uPSIxLjEiIHhtbG5zPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwL3N2ZyIgCiAgICAgICAgICAgICAgICAgICB4bWxuczp4bGluaz0iaHR0cDovL3d3dy53My5vcmcvMTk5OS94bGluayIgCiAgICAgICAgICAgICAgICAgICB2aWV3Qm94PSIwIDAgNjk2IDI1OCIgCiAgICAgICAgICAgICAgICAgICBwcmVzZXJ2ZUFzcGVjdFJhdGlvPSJ4TWlkWU1pZCBtZWV0Ij4KPGc+Cgk8cGF0aCBmaWxsPSIjQURFMEU0IiBkPSJNMC43ODcsNTMuODI1aDQxLjY2OXYxMTMuODM4aDcyLjgxNHYzNi41MTFIMC43ODdWNTMuODI1eiIvPgoJPHBhdGggZmlsbD0iI0FERTBFNCIgZD0iTTEzMy4xMDUsNTMuODI1aDEyMC4yNzV2MzYuNTE0aC03OC42MXYyNS41Nmg3MS4wOTN2MzQuNTgyaC03MS4wOTN2NTMuNjk0aC00MS42NjVWNTMuODI1eiIvPgoJPHBhdGggZmlsbD0iI0FERTBFNCIgZD0iTTI2Ny4xMzQsMTI5LjQyOXYtMC40MjdjMC00My44MTYsMzQuMzY0LTc4LjE4Miw4MC45NzQtNzguMTgyYzI2LjQyMSwwLDQ1LjEwNyw4LjE2MSw2MSwyMS45MDgKCQlsLTI0LjQ4NiwyOS40MjNjLTEwLjc0LTkuMDE5LTIxLjQ3OS0xNC4xNzItMzYuMjk0LTE0LjE3MmMtMjEuNjk1LDAtMzguNDUyLDE4LjI1NC0zOC40NTIsNDEuMjM5djAuNDI1CgkJYzAsMjQuMjczLDE2Ljk2Niw0MS42NzIsNDAuODA0LDQxLjY3MmMxMC4xMDMsMCwxNy44MzYtMi4xNDYsMjQuMDYzLTYuMjMxdi0xOC4yNTdoLTI5LjY0M3YtMzAuNWg2OS4xNTl2NjcuNjU5CgkJYy0xNS44OTMsMTMuMTA0LTM4LjAxNiwyMy4xOTctNjUuMjkxLDIzLjE5N0MzMDIuMTQ3LDIwNy4xODIsMjY3LjEzNCwxNzQuOTY0LDI2Ny4xMzQsMTI5LjQyOXoiLz4KCTxwYXRoIGZpbGw9IiNBREUwRTQiIGQ9Ik00MjYuMDg3LDE4MS44MzdsMjMuMTk1LTI3LjcwOWMxNC44MjIsMTEuODE2LDMxLjM2MSwxOC4wNDEsNDguNzU1LDE4LjA0MQoJCWMxMS4xNzEsMCwxNy4xODYtMy44NjYsMTcuMTg2LTEwLjMwNnYtMC40MzdjMC02LjIyNS00Ljk0LTkuNjY1LTI1LjM0Ny0xNC4zODdjLTMyLjAwNi03LjMwMi01Ni43MDItMTYuMzIxLTU2LjcwMi00Ny4yNXYtMC40MwoJCWMwLTI3LjkyMiwyMi4xMjMtNDguMTEzLDU4LjItNDguMTEzYzI1LjU2NCwwLDQ1LjU0Miw2Ljg3NSw2MS44NTgsMTkuOTczbC0yMC44MjksMjkuNDI5CgkJYy0xMy43NDctOS42NjgtMjguNzc4LTE0LjgxOC00Mi4wOTYtMTQuODE4Yy0xMC4wOTcsMC0xNS4wMzcsNC4yOTQtMTUuMDM3LDkuNjYzdjAuNDNjMCw2Ljg2OSw1LjE1NSw5Ljg4MSwyNS45OTIsMTQuNjA2CgkJYzM0LjU3OSw3LjUxNiw1Ni4wNTcsMTguNjg3LDU2LjA1Nyw0Ni44MTl2MC40MjdjMCwzMC43MTUtMjQuMjcxLDQ4Ljk2OS02MC43ODQsNDguOTY5CgkJQzQ2OS45MDEsMjA2Ljc0NCw0NDQuNTU3LDE5OC4zNzIsNDI2LjA4NywxODEuODM3eiIvPgoJPHBhdGggZmlsbD0iI0FERTBFNCIgZD0iTTU2My45ODQsMTgxLjgzN2wyMy4xOTEtMjcuNzA5YzE0LjgyNCwxMS44MTYsMzEuMzYyLDE4LjA0MSw0OC43NTUsMTguMDQxCgkJYzExLjE3NCwwLDE3LjE4OC0zLjg2NiwxNy4xODgtMTAuMzA2di0wLjQzN2MwLTYuMjI1LTQuOTQyLTkuNjY1LTI1LjM0NC0xNC4zODdjLTMyLjAwNS03LjMwMi01Ni43MDUtMTYuMzIxLTU2LjcwNS00Ny4yNXYtMC40MwoJCWMwLTI3LjkyMiwyMi4xMjMtNDguMTEzLDU4LjIwNS00OC4xMTNjMjUuNTU5LDAsNDUuNTM1LDYuODc1LDYxLjg1OSwxOS45NzNsLTIwLjgzOSwyOS40MjkKCQljLTEzLjc0LTkuNjY4LTI4Ljc3My0xNC44MTgtNDIuMDk3LTE0LjgxOGMtMTAuMDkxLDAtMTUuMDM1LDQuMjk0LTE1LjAzNSw5LjY2M3YwLjQzYzAsNi44NjksNS4xNTksOS44ODEsMjUuOTk1LDE0LjYwNgoJCWMzNC41NzksNy41MTYsNTYuMDU1LDE4LjY4Nyw1Ni4wNTUsNDYuODE5djAuNDI3YzAsMzAuNzE1LTI0LjI3LDQ4Ljk2OS02MC43ODUsNDguOTY5CgkJQzYwNy43OTgsMjA2Ljc0NCw1ODIuNDUzLDE5OC4zNzIsNTYzLjk4NCwxODEuODM3eiIvPgo8L2c+Cjwvc3ZnPgo=')"></p>`,
			expected: `<p style="width:100%;height:100%;background-image: url(&#39;data:image/svg+xml;base64,PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0idXRmLTgiPz4KPCFET0NUWVBFIHN2ZyBQVUJMSUMgIi0vL1czQy8vRFREIFNWRyAxLjEvL0VOIiAiaHR0cDovL3d3dy53My5vcmcvR3JhcGhpY3MvU1ZHLzEuMS9EVEQvc3ZnMTEuZHRkIj4KPHN2ZyB2ZXJzaW9uPSIxLjEiIHhtbG5zPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwL3N2ZyIgCiAgICAgICAgICAgICAgICAgICB4bWxuczp4bGluaz0iaHR0cDovL3d3dy53My5vcmcvMTk5OS94bGluayIgCiAgICAgICAgICAgICAgICAgICB2aWV3Qm94PSIwIDAgNjk2IDI1OCIgCiAgICAgICAgICAgICAgICAgICBwcmVzZXJ2ZUFzcGVjdFJhdGlvPSJ4TWlkWU1pZCBtZWV0Ij4KPGc+Cgk8cGF0aCBmaWxsPSIjQURFMEU0IiBkPSJNMC43ODcsNTMuODI1aDQxLjY2OXYxMTMuODM4aDcyLjgxNHYzNi41MTFIMC43ODdWNTMuODI1eiIvPgoJPHBhdGggZmlsbD0iI0FERTBFNCIgZD0iTTEzMy4xMDUsNTMuODI1aDEyMC4yNzV2MzYuNTE0aC03OC42MXYyNS41Nmg3MS4wOTN2MzQuNTgyaC03MS4wOTN2NTMuNjk0aC00MS42NjVWNTMuODI1eiIvPgoJPHBhdGggZmlsbD0iI0FERTBFNCIgZD0iTTI2Ny4xMzQsMTI5LjQyOXYtMC40MjdjMC00My44MTYsMzQuMzY0LTc4LjE4Miw4MC45NzQtNzguMTgyYzI2LjQyMSwwLDQ1LjEwNyw4LjE2MSw2MSwyMS45MDgKCQlsLTI0LjQ4NiwyOS40MjNjLTEwLjc0LTkuMDE5LTIxLjQ3OS0xNC4xNzItMzYuMjk0LTE0LjE3MmMtMjEuNjk1LDAtMzguNDUyLDE4LjI1NC0zOC40NTIsNDEuMjM5djAuNDI1CgkJYzAsMjQuMjczLDE2Ljk2Niw0MS42NzIsNDAuODA0LDQxLjY3MmMxMC4xMDMsMCwxNy44MzYtMi4xNDYsMjQuMDYzLTYuMjMxdi0xOC4yNTdoLTI5LjY0M3YtMzAuNWg2OS4xNTl2NjcuNjU5CgkJYy0xNS44OTMsMTMuMTA0LTM4LjAxNiwyMy4xOTctNjUuMjkxLDIzLjE5N0MzMDIuMTQ3LDIwNy4xODIsMjY3LjEzNCwxNzQuOTY0LDI2Ny4xMzQsMTI5LjQyOXoiLz4KCTxwYXRoIGZpbGw9IiNBREUwRTQiIGQ9Ik00MjYuMDg3LDE4MS44MzdsMjMuMTk1LTI3LjcwOWMxNC44MjIsMTEuODE2LDMxLjM2MSwxOC4wNDEsNDguNzU1LDE4LjA0MQoJCWMxMS4xNzEsMCwxNy4xODYtMy44NjYsMTcuMTg2LTEwLjMwNnYtMC40MzdjMC02LjIyNS00Ljk0LTkuNjY1LTI1LjM0Ny0xNC4zODdjLTMyLjAwNi03LjMwMi01Ni43MDItMTYuMzIxLTU2LjcwMi00Ny4yNXYtMC40MwoJCWMwLTI3LjkyMiwyMi4xMjMtNDguMTEzLDU4LjItNDguMTEzYzI1LjU2NCwwLDQ1LjU0Miw2Ljg3NSw2MS44NTgsMTkuOTczbC0yMC44MjksMjkuNDI5CgkJYy0xMy43NDctOS42NjgtMjguNzc4LTE0LjgxOC00Mi4wOTYtMTQuODE4Yy0xMC4wOTcsMC0xNS4wMzcsNC4yOTQtMTUuMDM3LDkuNjYzdjAuNDNjMCw2Ljg2OSw1LjE1NSw5Ljg4MSwyNS45OTIsMTQuNjA2CgkJYzM0LjU3OSw3LjUxNiw1Ni4wNTcsMTguNjg3LDU2LjA1Nyw0Ni44MTl2MC40MjdjMCwzMC43MTUtMjQuMjcxLDQ4Ljk2OS02MC43ODQsNDguOTY5CgkJQzQ2OS45MDEsMjA2Ljc0NCw0NDQuNTU3LDE5OC4zNzIsNDI2LjA4NywxODEuODM3eiIvPgoJPHBhdGggZmlsbD0iI0FERTBFNCIgZD0iTTU2My45ODQsMTgxLjgzN2wyMy4xOTEtMjcuNzA5YzE0LjgyNCwxMS44MTYsMzEuMzYyLDE4LjA0MSw0OC43NTUsMTguMDQxCgkJYzExLjE3NCwwLDE3LjE4OC0zLjg2NiwxNy4xODgtMTAuMzA2di0wLjQzN2MwLTYuMjI1LTQuOTQyLTkuNjY1LTI1LjM0NC0xNC4zODdjLTMyLjAwNS03LjMwMi01Ni43MDUtMTYuMzIxLTU2LjcwNS00Ny4yNXYtMC40MwoJCWMwLTI3LjkyMiwyMi4xMjMtNDguMTEzLDU4LjIwNS00OC4xMTNjMjUuNTU5LDAsNDUuNTM1LDYuODc1LDYxLjg1OSwxOS45NzNsLTIwLjgzOSwyOS40MjkKCQljLTEzLjc0LTkuNjY4LTI4Ljc3My0xNC44MTgtNDIuMDk3LTE0LjgxOGMtMTAuMDkxLDAtMTUuMDM1LDQuMjk0LTE1LjAzNSw5LjY2M3YwLjQzYzAsNi44NjksNS4xNTksOS44ODEsMjUuOTk1LDE0LjYwNgoJCWMzNC41NzksNy41MTYsNTYuMDU1LDE4LjY4Nyw1Ni4wNTUsNDYuODE5djAuNDI3YzAsMzAuNzE1LTI0LjI3LDQ4Ljk2OS02MC43ODUsNDguOTY5CgkJQzYwNy43OTgsMjA2Ljc0NCw1ODIuNDUzLDE5OC4zNzIsNTYzLjk4NCwxODEuODM3eiIvPgo8L2c+Cjwvc3ZnPgo=&#39;)"></p>`,
		},
	}

	p := UGCPolicy()
	p.AllowAttrs("style").OnElements("p")

	// These tests are run concurrently to enable the race detector to pick up
	// potential issues
	wg := sync.WaitGroup{}
	wg.Add(len(tests))
	for ii, tt := range tests {
		go func(ii int, tt test) {
			out := p.Sanitize(tt.in)
			if out != tt.expected {
				t.Errorf(
					"test %d failed;\ninput   : %s\noutput  : %s\nexpected: %s",
					ii,
					tt.in,
					out,
					tt.expected,
				)
			}
			wg.Done()
		}(ii, tt)
	}
	wg.Wait()
}

func TestIssue143(t *testing.T) {
	// HTML escaping of attribute values appears to occur twice
	tests := []test{
		{
			in:       `<p title='"'></p>`,
			expected: `<p title="&#34;"></p>`,
		},
		{
			in:       `<p title="&quot;"></p>`,
			expected: `<p title="&#34;"></p>`,
		},
		{
			in:       `<p title="&nbsp;"></p>`,
			expected: `<p title=" "></p>`,
		},
	}

	p := UGCPolicy()
	p.AllowAttrs("title").OnElements("p")

	// These tests are run concurrently to enable the race detector to pick up
	// potential issues
	wg := sync.WaitGroup{}
	wg.Add(len(tests))
	for ii, tt := range tests {
		go func(ii int, tt test) {
			out := p.Sanitize(tt.in)
			if out != tt.expected {
				t.Errorf(
					"test %d failed;\ninput   : %s\noutput  : %s\nexpected: %s",
					ii,
					tt.in,
					out,
					tt.expected,
				)
			}
			wg.Done()
		}(ii, tt)
	}
	wg.Wait()
}

func TestIssue146(t *testing.T) {
	// https://github.com/microcosm-cc/bluemonday/issues/146
	//
	// Ask for image/svg+xml to be accepted.
	// This blog https://digi.ninja/blog/svg_xss.php shows that inline images
	// that are SVG are considered safe, so I've added that and this test
	// verifies that it works.
	p := NewPolicy()
	p.AllowImages()
	p.AllowDataURIImages()

	input := `<img src="data:image/svg+xml;base64,PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0idXRmLTgiPz4KPCFET0NUWVBFIHN2ZyBQVUJMSUMgIi0vL1czQy8vRFREIFNWRyAxLjEvL0VOIiAiaHR0cDovL3d3dy53My5vcmcvR3JhcGhpY3MvU1ZHLzEuMS9EVEQvc3ZnMTEuZHRkIj4KPHN2ZyB2ZXJzaW9uPSIxLjEiIHhtbG5zPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwL3N2ZyIgCiAgICAgICAgICAgICAgICAgICB4bWxuczp4bGluaz0iaHR0cDovL3d3dy53My5vcmcvMTk5OS94bGluayIgCiAgICAgICAgICAgICAgICAgICB2aWV3Qm94PSIwIDAgNjk2IDI1OCIgCiAgICAgICAgICAgICAgICAgICBwcmVzZXJ2ZUFzcGVjdFJhdGlvPSJ4TWlkWU1pZCBtZWV0Ij4KPGc+Cgk8cGF0aCBmaWxsPSIjQURFMEU0IiBkPSJNMC43ODcsNTMuODI1aDQxLjY2OXYxMTMuODM4aDcyLjgxNHYzNi41MTFIMC43ODdWNTMuODI1eiIvPgoJPHBhdGggZmlsbD0iI0FERTBFNCIgZD0iTTEzMy4xMDUsNTMuODI1aDEyMC4yNzV2MzYuNTE0aC03OC42MXYyNS41Nmg3MS4wOTN2MzQuNTgyaC03MS4wOTN2NTMuNjk0aC00MS42NjVWNTMuODI1eiIvPgoJPHBhdGggZmlsbD0iI0FERTBFNCIgZD0iTTI2Ny4xMzQsMTI5LjQyOXYtMC40MjdjMC00My44MTYsMzQuMzY0LTc4LjE4Miw4MC45NzQtNzguMTgyYzI2LjQyMSwwLDQ1LjEwNyw4LjE2MSw2MSwyMS45MDgKCQlsLTI0LjQ4NiwyOS40MjNjLTEwLjc0LTkuMDE5LTIxLjQ3OS0xNC4xNzItMzYuMjk0LTE0LjE3MmMtMjEuNjk1LDAtMzguNDUyLDE4LjI1NC0zOC40NTIsNDEuMjM5djAuNDI1CgkJYzAsMjQuMjczLDE2Ljk2Niw0MS42NzIsNDAuODA0LDQxLjY3MmMxMC4xMDMsMCwxNy44MzYtMi4xNDYsMjQuMDYzLTYuMjMxdi0xOC4yNTdoLTI5LjY0M3YtMzAuNWg2OS4xNTl2NjcuNjU5CgkJYy0xNS44OTMsMTMuMTA0LTM4LjAxNiwyMy4xOTctNjUuMjkxLDIzLjE5N0MzMDIuMTQ3LDIwNy4xODIsMjY3LjEzNCwxNzQuOTY0LDI2Ny4xMzQsMTI5LjQyOXoiLz4KCTxwYXRoIGZpbGw9IiNBREUwRTQiIGQ9Ik00MjYuMDg3LDE4MS44MzdsMjMuMTk1LTI3LjcwOWMxNC44MjIsMTEuODE2LDMxLjM2MSwxOC4wNDEsNDguNzU1LDE4LjA0MQoJCWMxMS4xNzEsMCwxNy4xODYtMy44NjYsMTcuMTg2LTEwLjMwNnYtMC40MzdjMC02LjIyNS00Ljk0LTkuNjY1LTI1LjM0Ny0xNC4zODdjLTMyLjAwNi03LjMwMi01Ni43MDItMTYuMzIxLTU2LjcwMi00Ny4yNXYtMC40MwoJCWMwLTI3LjkyMiwyMi4xMjMtNDguMTEzLDU4LjItNDguMTEzYzI1LjU2NCwwLDQ1LjU0Miw2Ljg3NSw2MS44NTgsMTkuOTczbC0yMC44MjksMjkuNDI5CgkJYy0xMy43NDctOS42NjgtMjguNzc4LTE0LjgxOC00Mi4wOTYtMTQuODE4Yy0xMC4wOTcsMC0xNS4wMzcsNC4yOTQtMTUuMDM3LDkuNjYzdjAuNDNjMCw2Ljg2OSw1LjE1NSw5Ljg4MSwyNS45OTIsMTQuNjA2CgkJYzM0LjU3OSw3LjUxNiw1Ni4wNTcsMTguNjg3LDU2LjA1Nyw0Ni44MTl2MC40MjdjMCwzMC43MTUtMjQuMjcxLDQ4Ljk2OS02MC43ODQsNDguOTY5CgkJQzQ2OS45MDEsMjA2Ljc0NCw0NDQuNTU3LDE5OC4zNzIsNDI2LjA4NywxODEuODM3eiIvPgoJPHBhdGggZmlsbD0iI0FERTBFNCIgZD0iTTU2My45ODQsMTgxLjgzN2wyMy4xOTEtMjcuNzA5YzE0LjgyNCwxMS44MTYsMzEuMzYyLDE4LjA0MSw0OC43NTUsMTguMDQxCgkJYzExLjE3NCwwLDE3LjE4OC0zLjg2NiwxNy4xODgtMTAuMzA2di0wLjQzN2MwLTYuMjI1LTQuOTQyLTkuNjY1LTI1LjM0NC0xNC4zODdjLTMyLjAwNS03LjMwMi01Ni43MDUtMTYuMzIxLTU2LjcwNS00Ny4yNXYtMC40MwoJCWMwLTI3LjkyMiwyMi4xMjMtNDguMTEzLDU4LjIwNS00OC4xMTNjMjUuNTU5LDAsNDUuNTM1LDYuODc1LDYxLjg1OSwxOS45NzNsLTIwLjgzOSwyOS40MjkKCQljLTEzLjc0LTkuNjY4LTI4Ljc3My0xNC44MTgtNDIuMDk3LTE0LjgxOGMtMTAuMDkxLDAtMTUuMDM1LDQuMjk0LTE1LjAzNSw5LjY2M3YwLjQzYzAsNi44NjksNS4xNTksOS44ODEsMjUuOTk1LDE0LjYwNgoJCWMzNC41NzksNy41MTYsNTYuMDU1LDE4LjY4Nyw1Ni4wNTUsNDYuODE5djAuNDI3YzAsMzAuNzE1LTI0LjI3LDQ4Ljk2OS02MC43ODUsNDguOTY5CgkJQzYwNy43OTgsMjA2Ljc0NCw1ODIuNDUzLDE5OC4zNzIsNTYzLjk4NCwxODEuODM3eiIvPgo8L2c+Cjwvc3ZnPgo=" alt="">`
	out := p.Sanitize(input)
	expected := `<img src="data:image/svg+xml;base64,PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0idXRmLTgiPz4KPCFET0NUWVBFIHN2ZyBQVUJMSUMgIi0vL1czQy8vRFREIFNWRyAxLjEvL0VOIiAiaHR0cDovL3d3dy53My5vcmcvR3JhcGhpY3MvU1ZHLzEuMS9EVEQvc3ZnMTEuZHRkIj4KPHN2ZyB2ZXJzaW9uPSIxLjEiIHhtbG5zPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwL3N2ZyIgCiAgICAgICAgICAgICAgICAgICB4bWxuczp4bGluaz0iaHR0cDovL3d3dy53My5vcmcvMTk5OS94bGluayIgCiAgICAgICAgICAgICAgICAgICB2aWV3Qm94PSIwIDAgNjk2IDI1OCIgCiAgICAgICAgICAgICAgICAgICBwcmVzZXJ2ZUFzcGVjdFJhdGlvPSJ4TWlkWU1pZCBtZWV0Ij4KPGc+Cgk8cGF0aCBmaWxsPSIjQURFMEU0IiBkPSJNMC43ODcsNTMuODI1aDQxLjY2OXYxMTMuODM4aDcyLjgxNHYzNi41MTFIMC43ODdWNTMuODI1eiIvPgoJPHBhdGggZmlsbD0iI0FERTBFNCIgZD0iTTEzMy4xMDUsNTMuODI1aDEyMC4yNzV2MzYuNTE0aC03OC42MXYyNS41Nmg3MS4wOTN2MzQuNTgyaC03MS4wOTN2NTMuNjk0aC00MS42NjVWNTMuODI1eiIvPgoJPHBhdGggZmlsbD0iI0FERTBFNCIgZD0iTTI2Ny4xMzQsMTI5LjQyOXYtMC40MjdjMC00My44MTYsMzQuMzY0LTc4LjE4Miw4MC45NzQtNzguMTgyYzI2LjQyMSwwLDQ1LjEwNyw4LjE2MSw2MSwyMS45MDgKCQlsLTI0LjQ4NiwyOS40MjNjLTEwLjc0LTkuMDE5LTIxLjQ3OS0xNC4xNzItMzYuMjk0LTE0LjE3MmMtMjEuNjk1LDAtMzguNDUyLDE4LjI1NC0zOC40NTIsNDEuMjM5djAuNDI1CgkJYzAsMjQuMjczLDE2Ljk2Niw0MS42NzIsNDAuODA0LDQxLjY3MmMxMC4xMDMsMCwxNy44MzYtMi4xNDYsMjQuMDYzLTYuMjMxdi0xOC4yNTdoLTI5LjY0M3YtMzAuNWg2OS4xNTl2NjcuNjU5CgkJYy0xNS44OTMsMTMuMTA0LTM4LjAxNiwyMy4xOTctNjUuMjkxLDIzLjE5N0MzMDIuMTQ3LDIwNy4xODIsMjY3LjEzNCwxNzQuOTY0LDI2Ny4xMzQsMTI5LjQyOXoiLz4KCTxwYXRoIGZpbGw9IiNBREUwRTQiIGQ9Ik00MjYuMDg3LDE4MS44MzdsMjMuMTk1LTI3LjcwOWMxNC44MjIsMTEuODE2LDMxLjM2MSwxOC4wNDEsNDguNzU1LDE4LjA0MQoJCWMxMS4xNzEsMCwxNy4xODYtMy44NjYsMTcuMTg2LTEwLjMwNnYtMC40MzdjMC02LjIyNS00Ljk0LTkuNjY1LTI1LjM0Ny0xNC4zODdjLTMyLjAwNi03LjMwMi01Ni43MDItMTYuMzIxLTU2LjcwMi00Ny4yNXYtMC40MwoJCWMwLTI3LjkyMiwyMi4xMjMtNDguMTEzLDU4LjItNDguMTEzYzI1LjU2NCwwLDQ1LjU0Miw2Ljg3NSw2MS44NTgsMTkuOTczbC0yMC44MjksMjkuNDI5CgkJYy0xMy43NDctOS42NjgtMjguNzc4LTE0LjgxOC00Mi4wOTYtMTQuODE4Yy0xMC4wOTcsMC0xNS4wMzcsNC4yOTQtMTUuMDM3LDkuNjYzdjAuNDNjMCw2Ljg2OSw1LjE1NSw5Ljg4MSwyNS45OTIsMTQuNjA2CgkJYzM0LjU3OSw3LjUxNiw1Ni4wNTcsMTguNjg3LDU2LjA1Nyw0Ni44MTl2MC40MjdjMCwzMC43MTUtMjQuMjcxLDQ4Ljk2OS02MC43ODQsNDguOTY5CgkJQzQ2OS45MDEsMjA2Ljc0NCw0NDQuNTU3LDE5OC4zNzIsNDI2LjA4NywxODEuODM3eiIvPgoJPHBhdGggZmlsbD0iI0FERTBFNCIgZD0iTTU2My45ODQsMTgxLjgzN2wyMy4xOTEtMjcuNzA5YzE0LjgyNCwxMS44MTYsMzEuMzYyLDE4LjA0MSw0OC43NTUsMTguMDQxCgkJYzExLjE3NCwwLDE3LjE4OC0zLjg2NiwxNy4xODgtMTAuMzA2di0wLjQzN2MwLTYuMjI1LTQuOTQyLTkuNjY1LTI1LjM0NC0xNC4zODdjLTMyLjAwNS03LjMwMi01Ni43MDUtMTYuMzIxLTU2LjcwNS00Ny4yNXYtMC40MwoJCWMwLTI3LjkyMiwyMi4xMjMtNDguMTEzLDU4LjIwNS00OC4xMTNjMjUuNTU5LDAsNDUuNTM1LDYuODc1LDYxLjg1OSwxOS45NzNsLTIwLjgzOSwyOS40MjkKCQljLTEzLjc0LTkuNjY4LTI4Ljc3My0xNC44MTgtNDIuMDk3LTE0LjgxOGMtMTAuMDkxLDAtMTUuMDM1LDQuMjk0LTE1LjAzNSw5LjY2M3YwLjQzYzAsNi44NjksNS4xNTksOS44ODEsMjUuOTk1LDE0LjYwNgoJCWMzNC41NzksNy41MTYsNTYuMDU1LDE4LjY4Nyw1Ni4wNTUsNDYuODE5djAuNDI3YzAsMzAuNzE1LTI0LjI3LDQ4Ljk2OS02MC43ODUsNDguOTY5CgkJQzYwNy43OTgsMjA2Ljc0NCw1ODIuNDUzLDE5OC4zNzIsNTYzLjk4NCwxODEuODM3eiIvPgo8L2c+Cjwvc3ZnPgo=" alt="">`
	if out != expected {
		t.Errorf(
			"test failed;\ninput   : %s\noutput  : %s\nexpected: %s",
			input,
			out,
			expected)
	}
}

func TestIssue147(t *testing.T) {
	// https://github.com/microcosm-cc/bluemonday/issues/147
	//
	// ```
	// p.AllowElementsMatching(regexp.MustCompile(`^custom-`))
	// p.AllowNoAttrs().Matching(regexp.MustCompile(`^custom-`))
	// ```
	// This does not work as expected. This looks like a limitation, and the
	// question is whether the matching has to be applied in a second location
	// to overcome the limitation.
	//
	// However the issue is really that the `.Matching()` returns an attribute
	// test that has to be bound to some elements, it isn't a global test.
	//
	// This should work:
	// ```
	// p.AllowNoAttrs().Matching(regexp.MustCompile(`^custom-`)).OnElementsMatching(regexp.MustCompile(`^custom-`))
	// ```
	p := NewPolicy()
	p.AllowNoAttrs().Matching(regexp.MustCompile(`^custom-`)).OnElementsMatching(regexp.MustCompile(`^custom-`))

	input := `<custom-component>example</custom-component>`
	out := p.Sanitize(input)
	expected := `<custom-component>example</custom-component>`
	if out != expected {
		t.Errorf(
			"test failed;\ninput   : %s\noutput  : %s\nexpected: %s",
			input,
			out,
			expected)
	}
}

func TestRemovingEmptySelfClosingTag(t *testing.T) {
	p := NewPolicy()

	// Only broke when attribute policy was specified.
	p.AllowAttrs("type").OnElements("input")

	input := `<input/>`
	out := p.Sanitize(input)
	expected := ``
	if out != expected {
		t.Errorf(
			"test failed;\ninput   : %s\noutput  : %s\nexpected: %s",
			input,
			out,
			expected)
	}
}

func TestIssue161(t *testing.T) {
	// https://github.com/microcosm-cc/bluemonday/issues/161
	//
	// ```
	// p.AllowElementsMatching(regexp.MustCompile(`^custom-`))
	// p.AllowNoAttrs().Matching(regexp.MustCompile(`^custom-`))
	// ```
	// This does not work as expected. This looks like a limitation, and the
	// question is whether the matching has to be applied in a second location
	// to overcome the limitation.
	//
	// However the issue is really that the `.Matching()` returns an attribute
	// test that has to be bound to some elements, it isn't a global test.
	//
	// This should work:
	// ```
	// p.AllowNoAttrs().Matching(regexp.MustCompile(`^custom-`)).OnElementsMatching(regexp.MustCompile(`^custom-`))
	// ```
	p := UGCPolicy()
	p.AllowElements("picture", "source")
	p.AllowAttrs("srcset", "src", "type", "media").OnElements("source")

	input := `<picture><source src="b.jpg" media="(prefers-color-scheme: dark)"></source><img src="a.jpg"></picture>`
	out := p.Sanitize(input)
	expected := input
	if out != expected {
		t.Errorf(
			"test failed;\ninput   : %s\noutput  : %s\nexpected: %s",
			input,
			out,
			expected)
	}
}

func TestIssue174(t *testing.T) {
	// https://github.com/microcosm-cc/bluemonday/issues/174
	//
	// Allow all URL schemes
	p := UGCPolicy()
	p.AllowURLSchemesMatching(regexp.MustCompile(`.+`))

	input := `<a href="cbthunderlink://somebase64string"></a>
<a href="matrix:roomid/psumPMeAfzgAeQpXMG:feneas.org?action=join"></a>
<a href="https://github.com"></a>`
	out := p.Sanitize(input)
	expected := `<a href="cbthunderlink://somebase64string" rel="nofollow"></a>
<a href="matrix:roomid/psumPMeAfzgAeQpXMG:feneas.org?action=join" rel="nofollow"></a>
<a href="https://github.com" rel="nofollow"></a>`
	if out != expected {
		t.Errorf(
			"test failed;\ninput   : %s\noutput  : %s\nexpected: %s",
			input,
			out,
			expected)
	}

	// Custom handling of specific URL schemes even if the regex allows all
	p.AllowURLSchemeWithCustomPolicy("javascript", func(*url.URL) bool {
		return false
	})

	input = `<a href="cbthunderlink://somebase64string"></a>
<a href="javascript:alert('test')">xss</a>`
	out = p.Sanitize(input)
	expected = `<a href="cbthunderlink://somebase64string" rel="nofollow"></a>
xss`
	if out != expected {
		t.Errorf(
			"test failed;\ninput   : %s\noutput  : %s\nexpected: %s",
			input,
			out,
			expected)
	}
}

func TestXSSGo18(t *testing.T) {
	p := UGCPolicy()

	tests := []test{
		{
			in:       `<IMG SRC="jav&#x0D;ascript:alert('XSS');">`,
			expected: ``,
		},
		{
			in:       "<IMG SRC=`javascript:alert(\"RSnake says, 'XSS'\")`>",
			expected: ``,
		},
	}

	// These tests are run concurrently to enable the race detector to pick up
	// potential issues
	wg := sync.WaitGroup{}
	wg.Add(len(tests))
	for ii, tt := range tests {
		go func(ii int, tt test) {
			out := p.Sanitize(tt.in)
			if out != tt.expected {
				t.Errorf(
					"test %d failed;\ninput   : %s\noutput  : %s\nexpected: %s",
					ii,
					tt.in,
					out,
					tt.expected,
				)
			}
			wg.Done()
		}(ii, tt)
	}
	wg.Wait()
}

func TestIssue208(t *testing.T) {
	// https://github.com/microcosm-cc/bluemonday/issues/208

	p := NewPolicy()
	p.AllowElements("span")
	p.AllowAttrs("title").Matching(Paragraph).Globally()
	p.AllowAttrs("title").Matching(regexp.MustCompile(`.*`)).Globally()

	input := `<span title="a">b</span>`
	out := p.Sanitize(input)
	expected := `<span title="a">b</span>`
	if out != expected {
		t.Errorf(
			"test failed;\ninput   : %s\noutput  : %s\nexpected: %s",
			input,
			out,
			expected)
	}
}

func TestCallbackForAttributes(t *testing.T) {
	tests := []test{
		{
			in:       `<a href="http://www.google.com">`,
			expected: `<a href="http://www.google.com/ATTR" target="_blank" rel="nofollow noopener">`,
		},
		{
			in:       `<A Href="?q=1">`,
			expected: `<a href="?q=2">`,
		},
		{
			in:       `<img src="giraffe.gif" />`,
			expected: `<img src="giraffe1.gif"/>`,
		},
		{
			in:       `<IMG Src="new.gif" />`,
			expected: ``,
		},
	}

	p := UGCPolicy()
	p.RequireParseableURLs(true)
	p.RequireNoFollowOnLinks(false)
	p.RequireNoFollowOnFullyQualifiedLinks(true)
	p.AddTargetBlankToFullyQualifiedLinks(true)

	p.SetCallbackForAttributes(func(t *html.Token) []html.Attribute {
		attrs := t.Attr
		switch t.DataAtom {
		case atom.Img:
			_, src := findAttribute("src", attrs)
			switch src.Val {
			case "giraffe.gif":
				src.Val = "giraffe1.gif"
			case "new.gif":
				return nil
			}
		case atom.A:
			_, href := findAttribute("href", attrs)
			switch href.Val {
			case "?q=1":
				href.Val = "?q=2"
			case "http://www.google.com":
				href.Val = "http://www.google.com/ATTR"
			}
		}
		return attrs
	})

	for _, tt := range tests {
		assert.Equal(t, tt.expected, p.Sanitize(tt.in))
	}
}

func findAttribute(name string, attrs []html.Attribute) (int, *html.Attribute) {
	i := slices.IndexFunc(attrs, func(a html.Attribute) bool {
		return a.Key == name && a.Namespace == ""
	})
	if i == -1 {
		return i, nil
	}
	return i, &attrs[i]
}

func TestRewriteURL(t *testing.T) {
	tests := []struct {
		name     string
		in       string
		expected string
	}{
		{
			name:     "abs",
			in:       `<a href="http://www.google.com">`,
			expected: `<a href="http://www.google.com" target="_blank" rel="nofollow noreferrer noopener">`,
		},
		{
			name:     "rel",
			in:       `<a href="/page2.html">`,
			expected: `<a href="https://example.com/page2.html" target="_blank" rel="nofollow noreferrer noopener">`,
		},
		{
			name:     "video poster",
			in:       `<video poster="giraffe.gif" />`,
			expected: `<video poster="https://example.com/giraffe.gif"/>`,
		},
		{
			name:     "video poster removed",
			in:       `<video poster="removeme.gif" />`,
			expected: `<video/>`,
		},
		{
			name: "img removed",
			in:   `<img src="removeme.gif" />`,
		},
	}

	pageURL, err := url.Parse("https://example.com/page.html")
	require.NoError(t, err)

	p := UGCPolicy().
		RequireNoReferrerOnLinks(true).
		AddTargetBlankToFullyQualifiedLinks(true)

	p.AllowAttrs("poster").OnElements("video")

	p.RewriteTokenURL(func(_ *html.Token, u *url.URL) *url.URL {
		if u.IsAbs() {
			return u
		}
		if u.EscapedPath() == "removeme.gif" {
			return nil
		}
		return pageURL.ResolveReference(u)
	})

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, p.Sanitize(tt.in))
		})
	}
}

func TestWithValues(t *testing.T) {
	p := NewPolicy()

	p.AllowAttrs("one").WithValues("two").OnElements("tag")
	input := `<tag one="two">test</tag>`
	assert.Equal(t, input, p.Sanitize(input))

	input = `<tag one="TWO">test</tag>`
	assert.Equal(t, input, p.Sanitize(input))

	input = `<tag one="three">test</tag>`
	assert.Equal(t, "test", p.Sanitize(input))

	p.AllowAttrs("one").WithValues("two", "three").OnElements("tag")
	input = `<tag one="three">test</tag>`
	assert.Equal(t, input, p.Sanitize(input))

	p.AllowAttrs("one").WithValues("two", "three", "four").OnElements("tag")
	input = `<tag one="four">test</tag>`
	assert.Equal(t, input, p.Sanitize(input))
}

func TestHidden(t *testing.T) {
	input := `<p>Before paragraph.</p><p hidden>This should <em>not</em> appear in the <strong>output</strong></p><p>After paragraph.</p>`
	expected := `<p>Before paragraph.</p><p>After paragraph.</p>`

	p := UGCPolicy()
	assert.Equal(t, expected, p.Sanitize(input))

	p.AddSpaceWhenStrippingTag(true)
	expected = `<p>Before paragraph.</p> <p>After paragraph.</p>`
	assert.Equal(t, expected, p.Sanitize(input))
}

func TestSrcSet(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "img srcset",
			input:    `<img srcset="https://example.org/example-320w.jpg, https://example.org/example-480w.jpg 1.5x, https://example.org/example-640w.jpg 2x, https://example.org/example-640w.jpg 640w" src="https://example.org/example-640w.jpg" alt="Example"/>`,
			expected: `<img srcset="https://example.org/example-320w.jpg, https://example.org/example-480w.jpg 1.5x, https://example.org/example-640w.jpg 2x, https://example.org/example-640w.jpg 640w" src="https://example.org/example-640w.jpg" alt="Example"/>`,
		},
		{
			name:     "source srcset",
			input:    `<source srcset="https://example.org/example-320w.jpg, https://example.org/example-480w.jpg 1.5x, https://example.org/example-640w.jpg 2x, https://example.org/example-640w.jpg 640w" src="https://example.org/example-640w.jpg"/>`,
			expected: `<source srcset="https://example.org/example-320w.jpg, https://example.org/example-480w.jpg 1.5x, https://example.org/example-640w.jpg 2x, https://example.org/example-640w.jpg 640w" src="https://example.org/example-640w.jpg"/>`,
		},
		{
			name:     "invalid srcset",
			input:    `<img srcset="://example.com/example-320w.jpg" src="example-640w.jpg" alt="Example"/>`,
			expected: `<img src="https://example.com/example-640w.jpg" alt="Example"/>`,
		},
		{
			name:  "invalid img",
			input: `<img srcset="://example.com/example-320w.jpg" src="://example.com/example-640w.jpg" alt="Example"/>`,
		},
		{
			name:  "invalid source",
			input: `<source srcset="://example.com/example-320w.jpg" src="://example.com/example-640w.jpg"/>`,
		},
		{
			name:     "srcset and no src",
			input:    `<img srcset="example-320w.jpg, example-480w.jpg 1.5x,   example-640w.jpg 2x, example-640w.jpg 640w" alt="Example"/>`,
			expected: `<img srcset="https://example.com/example-320w.jpg, https://example.com/example-480w.jpg 1.5x, https://example.com/example-640w.jpg 2x, https://example.com/example-640w.jpg 640w" alt="Example"/>`,
		},
		{
			name:  "removed by rewriter",
			input: `<img src="removeMe.gif" alt="Example"/>`,
		},
		{
			name:     "with relative URLs",
			input:    `<img srcset="example-320w.jpg, example-480w.jpg 1.5x,   example-640,w.jpg 2x, example-640w.jpg 640w"/>`,
			expected: `<img srcset="https://example.com/example-320w.jpg, https://example.com/example-480w.jpg 1.5x, https://example.com/example-640,w.jpg 2x, https://example.com/example-640w.jpg 640w"/>`,
		},
		{
			name:     "with absolute URLs",
			input:    `<img srcset="http://example.org/example-320w.jpg 320w, http://example.org/example-480w.jpg 1.5x"/>`,
			expected: `<img srcset="http://example.org/example-320w.jpg 320w, http://example.org/example-480w.jpg 1.5x"/>`,
		},
		{
			name:     "with one candidate",
			input:    `<img srcset="http://example.org/example-320w.jpg"/>`,
			expected: `<img srcset="http://example.org/example-320w.jpg"/>`,
		},
		{
			name:     "with comma URL",
			input:    `<img srcset="http://example.org/example,a:b/d.jpg , example-480w.jpg 1.5x"/>`,
			expected: `<img srcset="http://example.org/example,a:b/d.jpg, https://example.com/example-480w.jpg 1.5x"/>`,
		},
		{
			name:  "with incorrect descriptor",
			input: `<img srcset="http://example.org/example-320w.jpg test"/>`,
		},
		{
			name:  "with too many descriptors",
			input: `<img srcset="http://example.org/example-320w.jpg 10w 1x"/>`,
		},
	}

	pageURL, err := url.Parse("https://example.com/page.html")
	require.NoError(t, err)

	p := UGCPolicy().AllowAttrs("src", "srcset").OnElements("source")
	p.RewriteTokenURL(func(_ *html.Token, u *url.URL) *url.URL {
		if u.IsAbs() {
			return u
		}
		return pageURL.ResolveReference(u)
	})

	p.RewriteSrc(func(u *url.URL) {
		if u.EscapedPath() == "/removeMe.gif" {
			*u = url.URL{}
		}
	})

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, p.Sanitize(tt.input))
		})
	}
}

func TestSetAttr(t *testing.T) {
	p := NewPolicy().AllowAttrs("src").OnElements("img")
	p.SetAttr("loading", "lazy").OnElements("img")

	input := `<img src="giraffe.gif"/>`
	expected := `<img src="giraffe.gif" loading="lazy"/>`
	assert.Equal(t, expected, p.Sanitize(input))

	input = `<img src="giraffe.gif" loading="lazy"/>`
	assert.Equal(t, input, p.Sanitize(input))

	p.AllowAttrs("loading").OnElements("img")
	assert.Equal(t, input, p.Sanitize(input))

	input = `<img src="giraffe.gif" loading="eager"/>`
	assert.Equal(t, expected, p.Sanitize(input))
}

func BenchmarkOpenPolicy(b *testing.B) {
	inputs := []string{githubHTML, wikipediaHTML}

	p := OpenPolicy()
	var r strings.Reader

	b.ReportAllocs()
	for b.Loop() {
		for _, s := range inputs {
			r.Reset(s)
			p.SanitizeReaderToWriter(&r, io.Discard)
		}
	}
}
