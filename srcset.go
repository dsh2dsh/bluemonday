package bluemonday

import (
	"net/url"
	"strconv"
	"strings"
)

type imageCandidates []*imageCandidate

// parseSrcSetAttribute returns the list of image candidates from the set.
// https://html.spec.whatwg.org/#parse-a-srcset-attribute
func (self *Policy) parseSrcSetAttribute(attr string) imageCandidates {
	n := strings.Count(attr, ", ")
	images := make(imageCandidates, 0, n+1)

	for value := range strings.SplitSeq(attr, ", ") {
		if image := parseImageCandidate(value, self.validURL); image != nil {
			images = append(images, image)
		}
	}
	return images
}

func (c imageCandidates) String() string {
	htmlCandidates := make([]string, len(c))
	for i, imageCandidate := range c {
		htmlCandidates[i] = imageCandidate.String()
	}
	return strings.Join(htmlCandidates, ", ")
}

type imageCandidate struct {
	ImageURL   string
	Descriptor string

	url *url.URL
}

func parseImageCandidate(input string, urlParser func(string) *url.URL,
) *imageCandidate {
	imageURL, descr, _ := strings.Cut(strings.TrimSpace(input), " ")
	u := urlParser(imageURL)
	if u == nil || !validWidthDensity(descr) {
		return nil
	}
	return &imageCandidate{ImageURL: u.String(), Descriptor: descr, url: u}
}

func validWidthDensity(value string) bool {
	if value == "" {
		return true
	} else if i := strings.Index(value, " "); i >= 0 {
		return false
	}

	lastChar := value[len(value)-1:]
	if lastChar != "w" && lastChar != "x" {
		return false
	}

	_, err := strconv.ParseFloat(value[0:len(value)-1], 32)
	return err == nil
}

func (self *imageCandidate) String() string {
	if self.Descriptor == "" {
		return self.ImageURL
	}
	return self.ImageURL + " " + self.Descriptor
}

func (self *imageCandidate) URL() *url.URL { return self.url }
