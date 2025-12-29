package bluemonday

import (
	"net/url"
	"strconv"
	"strings"
)

type ImageCandidates []ImageCandidate

// ParseSrcSetAttribute returns the list of image candidates from the set.
// https://html.spec.whatwg.org/#parse-a-srcset-attribute
func ParseSrcSetAttribute(attr string) ImageCandidates {
	return parseSrcSetAttribute(attr, func(s string) *url.URL {
		u, err := url.Parse(s)
		if err != nil {
			return nil
		}
		return u
	})
}

func parseSrcSetAttribute(attr string, urlParser func(string) *url.URL,
) ImageCandidates {
	n := strings.Count(attr, ", ")
	images := make(ImageCandidates, 0, n+1)

	for value := range strings.SplitSeq(attr, ", ") {
		if image := parseImageCandidate(value, urlParser); image.valid {
			images = append(images, image)
		}
	}
	return images
}

func (c ImageCandidates) String() string {
	htmlCandidates := make([]string, len(c))
	for i, imageCandidate := range c {
		htmlCandidates[i] = imageCandidate.String()
	}
	return strings.Join(htmlCandidates, ", ")
}

type ImageCandidate struct {
	ImageURL   string
	Descriptor string

	valid bool
}

func parseImageCandidate(input string, urlParser func(string) *url.URL,
) ImageCandidate {
	imageURL, descr, _ := strings.Cut(strings.TrimSpace(input), " ")
	u := urlParser(imageURL)
	if u == nil || !validWidthDensity(descr) {
		return ImageCandidate{}
	}
	return ImageCandidate{ImageURL: u.String(), Descriptor: descr, valid: true}
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

func (self *ImageCandidate) String() string {
	if self.Descriptor == "" {
		return self.ImageURL
	}
	return self.ImageURL + " " + self.Descriptor
}
