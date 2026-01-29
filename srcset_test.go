package bluemonday

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseSrcSetAttribute(t *testing.T) {
	tests := []struct {
		name     string
		srcset   string
		expected string
	}{
		{
			name:     "comma no space",
			srcset:   "http://example.org/example-320w.jpg 320w,http://example.org/example-480w.jpg 1.5x",
			expected: "http://example.org/example-320w.jpg 320w, http://example.org/example-480w.jpg 1.5x",
		},
		{
			name:     "comma with space",
			srcset:   "http://example.org/example-320w.jpg 320w, http://example.org/example-480w.jpg 1.5x",
			expected: "http://example.org/example-320w.jpg 320w, http://example.org/example-480w.jpg 1.5x",
		},
		{
			name:     "only URL with comma",
			srcset:   "http://example.org/example-320w,123.jpg",
			expected: "http://example.org/example-320w,123.jpg",
		},
		{
			name:     "only URL with comma and descr",
			srcset:   "http://example.org/example-320w,123.jpg 320w",
			expected: "http://example.org/example-320w,123.jpg 320w",
		},
		{
			name:     "candidate with comma",
			srcset:   "http://example.org/example-320w,123.jpg 320w,http://example.org/example-480w.jpg 1.5x",
			expected: "http://example.org/example-320w,123.jpg 320w, http://example.org/example-480w.jpg 1.5x",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, ParseSrcSetAttribute(tt.srcset).String())
		})
	}
}
