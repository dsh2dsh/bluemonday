package bluemonday

import (
	"iter"
	"net/url"
	"slices"
	"strconv"
	"strings"
)

type ImageCandidates []ImageCandidate

// ParseSrcSetAttribute returns the list of image candidates from the set.
// https://html.spec.whatwg.org/#parse-a-srcset-attribute
func ParseSrcSetAttribute(attr string) ImageCandidates {
	urlParser := func(s string) *url.URL {
		u, err := url.Parse(s)
		if err != nil {
			return nil
		}
		return u
	}
	return slices.Collect(parseSrcsetSeq(attr, urlParser))
}

func parseSrcsetSeq(attr string, urlParser func(string) *url.URL,
) iter.Seq[ImageCandidate] {
	return func(yield func(ImageCandidate) bool) {
		for s := range splitSrcset(attr) {
			if image := parseImageCandidate(s, urlParser); !image.Empty() {
				if !yield(image) {
					return
				}
			}
		}
	}
}

func splitSrcset(attr string) iter.Seq[string] {
	return func(yield func(string) bool) {
		attr = strings.TrimSpace(attr)
		for i := 0; ; {
			s := attr[i:]
			comma := strings.Index(s, ",")
			if comma == -1 || comma+1 == len(s) {
				yield(attr)
				return
			}

			comma += i
			s, nextChar := attr[:comma], comma+1
			if attr[nextChar] != ' ' && !strings.Contains(s, " ") {
				i = nextChar
				continue
			}

			if !yield(s) {
				return
			}
			attr, i = strings.TrimLeft(attr[nextChar:], " "), 0
		}
	}
}

func (self ImageCandidates) String() string {
	htmlCandidates := make([]string, len(self))
	for i, imageCandidate := range self {
		htmlCandidates[i] = imageCandidate.String()
	}
	return strings.Join(htmlCandidates, ", ")
}

type ImageCandidate struct {
	URL        string
	Descriptor string
}

func parseImageCandidate(input string, urlParser func(string) *url.URL,
) ImageCandidate {
	imageURL, descr, _ := strings.Cut(strings.TrimSpace(input), " ")
	u := urlParser(imageURL)
	if u == nil || !validWidthDensity(descr) {
		return ImageCandidate{}
	}
	return ImageCandidate{URL: u.String(), Descriptor: descr}
}

func validWidthDensity(value string) bool {
	if value == "" {
		return true
	} else if strings.Contains(value, " ") {
		return false
	}

	lastChar := value[len(value)-1:]
	if lastChar != "w" && lastChar != "x" {
		return false
	}

	_, err := strconv.ParseFloat(value[0:len(value)-1], 32)
	return err == nil
}

func (self *ImageCandidate) Empty() bool {
	return self.URL == "" && self.Descriptor == ""
}

func (self *ImageCandidate) String() string {
	if self.Descriptor == "" {
		return self.URL
	}
	return self.URL + " " + self.Descriptor
}
