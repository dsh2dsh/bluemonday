package bluemonday

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPolicy_SetAttrIf_domainIn(t *testing.T) {
	tests := []struct {
		name       string
		hostname   string
		expected   string
		policyFunc func(p *Policy)
	}{
		{
			hostname: "youtube.com",
			expected: `<iframe src="https://youtube.com/embed/test123" referrerpolicy="strict-origin-when-cross-origin"></iframe>`,
		},
		{
			hostname: "www.youtube.com",
			expected: `<iframe src="https://www.youtube.com/embed/test123" referrerpolicy="strict-origin-when-cross-origin"></iframe>`,
		},
		{
			hostname: "youtube-nocookie.com",
			expected: `<iframe src="https://youtube-nocookie.com/embed/test123" referrerpolicy="strict-origin-when-cross-origin"></iframe>`,
		},
		{
			hostname: "notyoutube.com",
			expected: `<iframe src="https://notyoutube.com/embed/test123"></iframe>`,
		},
		{
			name:     "without parseable URLs",
			hostname: "youtube.com",
			expected: `<iframe src="https://youtube.com/embed/test123"></iframe>`,
			policyFunc: func(p *Policy) {
				p.RequireParseableURLs(false)
			},
		},
	}

	const iframeTmpl = `<iframe src="https://%s/embed/test123"></iframe>`

	p := UGCPolicy()
	p.AllowAttrs("src").OnElements("iframe")
	p.SetAttrIf("referrerpolicy", "strict-origin-when-cross-origin",
		DomainIn("youtube.com", "youtube-nocookie.com"),
	).OnElements("iframe")

	for _, tt := range tests {
		name := tt.name
		if name == "" {
			name = tt.hostname
		}

		t.Run(name, func(t *testing.T) {
			if tt.policyFunc != nil {
				tt.policyFunc(p)
			}
			in := fmt.Sprintf(iframeTmpl, tt.hostname)
			assert.Equal(t, tt.expected, p.Sanitize(in))
		})
	}
}
