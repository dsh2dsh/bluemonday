package css

import (
	"regexp"
	"testing"

	"github.com/stretchr/testify/assert"
)

func trueHandler(s string) bool { return true }

func TestStyleOnElementMatching(t *testing.T) {
	type tagStyle struct {
		tag, style string
	}

	tests := []struct {
		msg      string
		policyFn func(policy *Policy)
		in       []tagStyle
		expected []string
	}{
		{
			msg: "Tags with style policy matching prefix should strip any that do not match with custom attr",
			policyFn: func(policy *Policy) {
				policy.AllowStyles("color", "mystyle").
					MatchingHandler(trueHandler).
					OnElementsMatching(regexp.MustCompile(`^my-element-`))
			},
			in: []tagStyle{
				{"my-element-demo-one", "color:#ffffff;mystyle:test;other:value"},
				{"my-element-demo-two", "other:value"},
				{"not-my-element-demo-one", ""},
			},
			expected: []string{"color: #ffffff; mystyle: test", "", ""},
		},
		{
			msg: "Specific element rule defined should override matching rules",
			policyFn: func(policy *Policy) {
				policy.AllowStyles("color", "mystyle").
					MatchingHandler(trueHandler).
					OnElements("my-element-demo-one")

				policy.AllowStyles("color", "customstyle").
					MatchingHandler(trueHandler).
					OnElementsMatching(regexp.MustCompile(`^my-element-`))
			},
			in: []tagStyle{
				{"my-element-demo-one", "color:#ffffff;mystyle:test;other:value"},
				{"my-element-demo-two", "color:#ffffff;mystyle:test;customstyle:value"},
				{"not-my-element-demo-one", ""},
			},
			expected: []string{
				"color: #ffffff; mystyle: test",
				"color: #ffffff; customstyle: value",
				"",
			},
		},
	}

	for _, tt := range tests {
		p := NewPolicy()
		if tt.policyFn != nil {
			tt.policyFn(p)
		}

		out := make([]string, len(tt.in))
		for i := range tt.in {
			out[i] = p.Sanitize(tt.in[i].tag, tt.in[i].style)
		}
		assert.Equal(t, tt.expected, out, tt.msg)
	}
}

func TestDefaultStyleHandlers(t *testing.T) {
	tests := []struct {
		in, expected []string
	}{
		{
			in:       []string{"nonexistentStyle: something;"},
			expected: []string{""},
		},
		{
			in:       []string{"aLiGn-cOntEnt: cEntEr;"},
			expected: []string{"aLiGn-cOntEnt: cEntEr"},
		},
		{
			in:       []string{"align-items: center;"},
			expected: []string{"align-items: center"},
		},
		{
			in:       []string{"align-self: center;"},
			expected: []string{"align-self: center"},
		},
		{
			in:       []string{"all: initial;"},
			expected: []string{"all: initial"},
		},
		{
			in: []string{
				"animation: mymove 5s infinite;", "animation: inherit;",
			},
			expected: []string{
				"animation: mymove 5s infinite", "animation: inherit",
			},
		},
		{
			in:       []string{"animation-delay: 2s;", "animation-delay: initial;"},
			expected: []string{"animation-delay: 2s", "animation-delay: initial"},
		},
		{
			in:       []string{"animation-direction: alternate;"},
			expected: []string{"animation-direction: alternate"},
		},
		{
			in: []string{
				"animation-duration: 2s;",
				"animation-duration: initial;",
			},
			expected: []string{
				"animation-duration: 2s",
				"animation-duration: initial",
			},
		},
		{
			in:       []string{"animation-fill-mode: forwards;"},
			expected: []string{"animation-fill-mode: forwards"},
		},
		{
			in: []string{
				"animation-iteration-count: 4;",
				"animation-iteration-count: inherit;",
			},
			expected: []string{
				"animation-iteration-count: 4",
				"animation-iteration-count: inherit",
			},
		},
		{
			in:       []string{"animation-name: chuck;", "animation-name: none"},
			expected: []string{"animation-name: chuck", "animation-name: none"},
		},
		{
			in:       []string{"animation-play-state: running;"},
			expected: []string{"animation-play-state: running"},
		},
		{
			in: []string{
				"animation-timing-function: cubic-bezier(1,1,1,1);",
				"animation-timing-function: steps(2, start);",
			},
			expected: []string{
				"animation-timing-function: cubic-bezier(1,1,1,1)",
				"animation-timing-function: steps(2, start)",
			},
		},
		{
			in:       []string{"backface-visibility: hidden"},
			expected: []string{"backface-visibility: hidden"},
		},
		{
			in: []string{
				"background: lightblue url('https://img_tree.gif') no-repeat fixed center",
				"background: initial",
			},
			expected: []string{
				"background: lightblue url('https://img_tree.gif') no-repeat fixed center",
				"background: initial",
			},
		},
		{
			in:       []string{"background-attachment: fixed"},
			expected: []string{"background-attachment: fixed"},
		},
		{
			in:       []string{"background-blend-mode: lighten"},
			expected: []string{"background-blend-mode: lighten"},
		},
		{
			in:       []string{"background-clip: padding-box"},
			expected: []string{"background-clip: padding-box"},
		},
		{
			in:       []string{"background-color: coral"},
			expected: []string{"background-color: coral"},
		},
		{
			in:       []string{"background-color: transparent"},
			expected: []string{"background-color: transparent"},
		},
		{
			in: []string{
				"background-image: url('http://paper.gif')",
				"background-image: inherit",
			},
			expected: []string{
				"background-image: url('http://paper.gif')",
				"background-image: inherit",
			},
		},
		{
			in:       []string{"background-origin: content-box"},
			expected: []string{"background-origin: content-box"},
		},
		{
			in: []string{
				"background-position: center",
				"background-position: 20px 20px",
			},
			expected: []string{
				"background-position: center",
				"background-position: 20px 20px",
			},
		},
		{
			in:       []string{"background-repeat: repeat-y"},
			expected: []string{"background-repeat: repeat-y"},
		},
		{
			in: []string{
				"background-size: 300px 100px",
				"background-size: initial",
			},
			expected: []string{
				"background-size: 300px 100px",
				"background-size: initial",
			},
		},
		{
			in:       []string{"border: 4px dotted blue;", "border: initial;"},
			expected: []string{"border: 4px dotted blue", "border: initial"},
		},
		{
			in: []string{
				"border-bottom: 4px dotted blue;",
				"border-bottom: initial",
			},
			expected: []string{
				"border-bottom: 4px dotted blue",
				"border-bottom: initial",
			},
		},
		{
			in:       []string{"border-bottom-color: blue;"},
			expected: []string{"border-bottom-color: blue"},
		},
		{
			in: []string{
				"border-bottom-left-radius: 4px;",
				"border-bottom-left-radius: initial",
			},
			expected: []string{
				"border-bottom-left-radius: 4px",
				"border-bottom-left-radius: initial",
			},
		},
		{
			in:       []string{"border-bottom-right-radius: 40px 4px;"},
			expected: []string{"border-bottom-right-radius: 40px 4px"},
		},
		{
			in:       []string{"border-bottom-style: dotted;"},
			expected: []string{"border-bottom-style: dotted"},
		},
		{
			in:       []string{"border-bottom-width: thin;"},
			expected: []string{"border-bottom-width: thin"},
		},
		{
			in:       []string{"border-collapse: separate;"},
			expected: []string{"border-collapse: separate"},
		},
		{
			in:       []string{"border-color: coral;"},
			expected: []string{"border-color: coral"},
		},
		{
			in: []string{
				"border-image: url(https://border.png) 30 round;",
				"border-image: initial;",
			},
			expected: []string{
				"border-image: url(https://border.png) 30 round",
				"border-image: initial",
			},
		},
		{
			in:       []string{"border-image-outset: 10px;"},
			expected: []string{"border-image-outset: 10px"},
		},
		{
			in:       []string{"border-image-repeat: repeat;"},
			expected: []string{"border-image-repeat: repeat"},
		},
		{
			in: []string{
				"border-image-slice: 30%;",
				"border-image-slice: fill;",
				"border-image-slice: 3% 3% 3% 3% 3%;",
			},
			expected: []string{
				"border-image-slice: 30%",
				"border-image-slice: fill",
				"",
			},
		},
		{
			in:       []string{"border-image-source: url(https://border.png);"},
			expected: []string{"border-image-source: url(https://border.png)"},
		},
		{
			in:       []string{"border-image-width: 10px;"},
			expected: []string{"border-image-width: 10px"},
		},
		{
			in:       []string{"border-left: 4px dotted blue;"},
			expected: []string{"border-left: 4px dotted blue"},
		},
		{
			in:       []string{"border-left-color: blue;"},
			expected: []string{"border-left-color: blue"},
		},
		{
			in:       []string{"border-left-style: dotted;"},
			expected: []string{"border-left-style: dotted"},
		},
		{
			in:       []string{"border-left-width: thin;"},
			expected: []string{"border-left-width: thin"},
		},
		{
			in: []string{
				"border-radius: 25px;",
				"border-radius: initial;",
				"border-radius: 1px 1px 1px 1px 1px;",
			},
			expected: []string{
				"border-radius: 25px",
				"border-radius: initial",
				"",
			},
		},
		{
			in:       []string{"border-left: 4px dotted blue;"},
			expected: []string{"border-left: 4px dotted blue"},
		},
		{
			in:       []string{"border-right-color: blue;"},
			expected: []string{"border-right-color: blue"},
		},
		{
			in:       []string{"border-right-style: dotted;"},
			expected: []string{"border-right-style: dotted"},
		},
		{
			in:       []string{"border-right-width: thin;"},
			expected: []string{"border-right-width: thin"},
		},
		{
			in:       []string{"border-spacing: 15px;"},
			expected: []string{"border-spacing: 15px"},
		},
		{
			in: []string{
				"border-style: dotted;",
				"border-style: initial;",
				"border-style: dotted dotted dotted dotted dotted;",
			},
			expected: []string{
				"border-style: dotted",
				"border-style: initial",
				"",
			},
		},
		{
			in:       []string{"border-top: 4px dotted blue;"},
			expected: []string{"border-top: 4px dotted blue"},
		},
		{
			in:       []string{"border-top-color: blue;"},
			expected: []string{"border-top-color: blue"},
		},
		{
			in:       []string{"border-top-left-radius: 4px;"},
			expected: []string{"border-top-left-radius: 4px"},
		},
		{
			in:       []string{"border-top-right-radius: 40px 4px;"},
			expected: []string{"border-top-right-radius: 40px 4px"},
		},
		{
			in:       []string{"border-top-style: dotted;"},
			expected: []string{"border-top-style: dotted"},
		},
		{
			in:       []string{"border-top-width: thin;"},
			expected: []string{"border-top-width: thin"},
		},
		{
			in: []string{
				"border-width: thin;",
				"border-width: initial;",
				"border-width: thin thin thin thin thin;",
			},
			expected: []string{
				"border-width: thin",
				"border-width: initial",
				"",
			},
		},
		{
			in:       []string{"bottom: 10px;", "bottom: auto;"},
			expected: []string{"bottom: 10px", "bottom: auto"},
		},
		{
			in:       []string{"box-decoration-break: slice;"},
			expected: []string{"box-decoration-break: slice"},
		},
		{
			in: []string{
				"box-shadow: 10px 10px #888888;",
				"box-shadow: aa;",
				"box-shadow: 10px aa;",
				"box-shadow: 10px;",
				"box-shadow: 10px 10px aa;",
			},
			expected: []string{
				"box-shadow: 10px 10px #888888",
				"",
				"",
				"",
				"",
			},
		},
		{
			in:       []string{"box-sizing: border-box;"},
			expected: []string{"box-sizing: border-box"},
		},
		{
			in:       []string{"break-after: column;"},
			expected: []string{"break-after: column"},
		},
		{
			in:       []string{"break-before: column;"},
			expected: []string{"break-before: column"},
		},
		{
			in:       []string{"break-inside: avoid-column;"},
			expected: []string{"break-inside: avoid-column"},
		},
		{
			in:       []string{"caption-side: bottom;"},
			expected: []string{"caption-side: bottom"},
		},
		{
			in: []string{
				"caret-color: red;",
				"caret-color: rgb(2,2,2);",
				"caret-color: rgba(2,2,2,0.5);",
				"caret-color: hsl(2,2%,2%);",
				"caret-color: hsla(2,2%,2%,0.5);",
			},
			expected: []string{
				"caret-color: red",
				"caret-color: rgb(2,2,2)",
				"caret-color: rgba(2,2,2,0.5)",
				"caret-color: hsl(2,2%,2%)",
				"caret-color: hsla(2,2%,2%,0.5)",
			},
		},
		{
			in:       []string{"clear: both;"},
			expected: []string{"clear: both"},
		},
		{
			in: []string{
				"clip: rect(0px,60px,200px,0px);",
				"clip: auto;",
			},
			expected: []string{
				"clip: rect(0px,60px,200px,0px)",
				"clip: auto",
			},
		},
		{
			in: []string{
				"color: red;",
				"color: rgb(2,2,2);",
				"color: rgba(2,2,2,0.5);",
				"color: hsl(2,2%,2%);",
				"color: hsla(2,2%,2%,0.5);",
			},
			expected: []string{
				"color: red",
				"color: rgb(2,2,2)",
				"color: rgba(2,2,2,0.5)",
				"color: hsl(2,2%,2%)",
				"color: hsla(2,2%,2%,0.5)",
			},
		},
		{
			in:       []string{"clear: both;"},
			expected: []string{"clear: both"},
		},
		{
			in:       []string{"column-count: 3;", "column-count: auto;"},
			expected: []string{"column-count: 3", "column-count: auto"},
		},
		{
			in:       []string{"column-fill: balance;"},
			expected: []string{"column-fill: balance"},
		},
		{
			in:       []string{"column-gap: 40px;", "column-gap: normal;"},
			expected: []string{"column-gap: 40px", "column-gap: normal"},
		},
		{
			in:       []string{"column-rule: 4px double #ff00ff;"},
			expected: []string{"column-rule: 4px double #ff00ff"},
		},
		{
			in:       []string{"column-rule-color: #ff00ff;"},
			expected: []string{"column-rule-color: #ff00ff"},
		},
		{
			in:       []string{"column-rule-color: #f0ff;"},
			expected: []string{"column-rule-color: #f0ff"},
		},
		{
			in:       []string{"column-rule: red;"},
			expected: []string{"column-rule: red"},
		},
		{
			in:       []string{"column-rule-width: 4px;"},
			expected: []string{"column-rule-width: 4px"},
		},
		{
			in:       []string{"column-span: all;"},
			expected: []string{"column-span: all"},
		},
		{
			in:       []string{"column-width: 4px;", "column-width: auto;"},
			expected: []string{"column-width: 4px", "column-width: auto"},
		},
		{
			in:       []string{"columns: 4px 3", "columns: auto"},
			expected: []string{"columns: 4px 3", "columns: auto"},
		},
		{
			in:       []string{"cursor: alias"},
			expected: []string{"cursor: alias"},
		},
		{
			in:       []string{"direction: rtl"},
			expected: []string{"direction: rtl"},
		},
		{
			in:       []string{"display: block"},
			expected: []string{"display: block"},
		},
		{
			in:       []string{"empty-cells: hide"},
			expected: []string{"empty-cells: hide"},
		},
		{
			in:       []string{"filter: grayscale(100%)", "filter: sepia(100%)"},
			expected: []string{"filter: grayscale(100%)", "filter: sepia(100%)"},
		},
		{
			in:       []string{"flex: 1", "flex: auto"},
			expected: []string{"flex: 1", "flex: auto"},
		},
		{
			in:       []string{"flex-basis: 10px", "flex-basis: auto"},
			expected: []string{"flex-basis: 10px", "flex-basis: auto"},
		},
		{
			in:       []string{"flex-direction: row-reverse"},
			expected: []string{"flex-direction: row-reverse"},
		},
		{
			in:       []string{"flex-flow: row-reverse wrap", "flex-flow: initial"},
			expected: []string{"flex-flow: row-reverse wrap", "flex-flow: initial"},
		},
		{
			in:       []string{"flex-grow: 1", "flex-grow: initial"},
			expected: []string{"flex-grow: 1", "flex-grow: initial"},
		},
		{
			in:       []string{"flex-shrink: 3"},
			expected: []string{"flex-shrink: 3"},
		},
		{
			in:       []string{"flex-wrap: wrap"},
			expected: []string{"flex-wrap: wrap"},
		},
		{
			in:       []string{"float: right"},
			expected: []string{"float: right"},
		},
		{
			in: []string{
				"font: italic bold 12px/30px Georgia, serif",
				"font: icon",
			},
			expected: []string{
				"font: italic bold 12px/30px Georgia, serif",
				"font: icon",
			},
		},
		{
			in: []string{
				"font-family: 'Times New Roman', Times, serif",
				"font-family: comic sans ms, cursive, sans-serif;",
			},
			expected: []string{
				"font-family: 'Times New Roman', Times, serif",
				"font-family: comic sans ms, cursive, sans-serif",
			},
		},
		{
			in:       []string{"font-kerning: normal"},
			expected: []string{"font-kerning: normal"},
		},
		{
			in:       []string{"font-language-override: normal"},
			expected: []string{"font-language-override: normal"},
		},
		{
			in:       []string{"font-size: large"},
			expected: []string{"font-size: large"},
		},
		{
			in:       []string{"font-size-adjust: 0.58", "font-size-adjust: auto"},
			expected: []string{"font-size-adjust: 0.58", "font-size-adjust: auto"},
		},
		{
			in:       []string{"font-stretch: expanded"},
			expected: []string{"font-stretch: expanded"},
		},
		{
			in:       []string{"font-style: italic"},
			expected: []string{"font-style: italic"},
		},
		{
			in:       []string{"font-synthesis: style"},
			expected: []string{"font-synthesis: style"},
		},
		{
			in:       []string{"font-variant: small-caps"},
			expected: []string{"font-variant: small-caps"},
		},
		{
			in:       []string{"font-variant-caps: small-caps"},
			expected: []string{"font-variant-caps: small-caps"},
		},
		{
			in:       []string{"font-variant-position: sub"},
			expected: []string{"font-variant-position: sub"},
		},
		{
			in:       []string{"font-weight: normal"},
			expected: []string{"font-weight: normal"},
		},
		{
			in:       []string{"grid: 150px / auto auto auto;", "grid: none;"},
			expected: []string{"grid: 150px / auto auto auto", "grid: none"},
		},
		{
			in:       []string{"grid-area: 2 / 1 / span 2 / span 3;"},
			expected: []string{"grid-area: 2 / 1 / span 2 / span 3"},
		},
		{
			in: []string{
				"grid-auto-columns: 150px;",
				"grid-auto-columns: auto;",
			},
			expected: []string{
				"grid-auto-columns: 150px",
				"grid-auto-columns: auto",
			},
		},
		{
			in:       []string{"grid-auto-flow: column;"},
			expected: []string{"grid-auto-flow: column"},
		},
		{
			in:       []string{"grid-auto-rows: 150px;"},
			expected: []string{"grid-auto-rows: 150px"},
		},
		{
			in:       []string{"grid-column: 1 / span 2;"},
			expected: []string{"grid-column: 1 / span 2"},
		},
		{
			in:       []string{"grid-column-end: span 2;", "grid-column-end: auto;"},
			expected: []string{"grid-column-end: span 2", "grid-column-end: auto"},
		},
		{
			in:       []string{"grid-column-gap: 10px;"},
			expected: []string{"grid-column-gap: 10px"},
		},
		{
			in:       []string{"grid-column-start: 1;"},
			expected: []string{"grid-column-start: 1"},
		},
		{
			in:       []string{"grid-gap: 1px;", "grid-gap: 1px 1px 1px;"},
			expected: []string{"grid-gap: 1px", ""},
		},
		{
			in:       []string{"grid-row: 1 / span 2;"},
			expected: []string{"grid-row: 1 / span 2"},
		},
		{
			in:       []string{"grid-row-end: span 2;"},
			expected: []string{"grid-row-end: span 2"},
		},
		{
			in:       []string{"grid-row-gap: 10px;"},
			expected: []string{"grid-row-gap: 10px"},
		},
		{
			in:       []string{"grid-row-start: 1;"},
			expected: []string{"grid-row-start: 1"},
		},
		{
			in: []string{
				"grid-template: 150px / auto auto auto;",
				"grid-template: none",
				"grid-template: a / a / a",
			},
			expected: []string{
				"grid-template: 150px / auto auto auto",
				"grid-template: none",
				"",
			},
		},
		{
			in: []string{
				"grid-template-areas: none;",
				"grid-template-areas: 'Billy'",
			},
			expected: []string{
				"grid-template-areas: none",
				"grid-template-areas: 'Billy'",
			},
		},
		{
			in:       []string{"grid-template-columns: auto auto auto auto auto;"},
			expected: []string{"grid-template-columns: auto auto auto auto auto"},
		},
		{
			in: []string{
				"grid-template-rows: 150px 150px",
				"grid-template-rows: aaaa aaaaa",
			},
			expected: []string{
				"grid-template-rows: 150px 150px",
				"",
			},
		},
		{
			in:       []string{"hanging-punctuation: first;"},
			expected: []string{"hanging-punctuation: first"},
		},
		{
			in:       []string{"height: 50px;", "height: auto;"},
			expected: []string{"height: 50px", "height: auto"},
		},
		{
			in:       []string{"hyphens: manual;"},
			expected: []string{"hyphens: manual"},
		},
		{
			in:       []string{"isolation: isolate;"},
			expected: []string{"isolation: isolate"},
		},
		{
			in:       []string{"image-rendering: smooth;"},
			expected: []string{"image-rendering: smooth"},
		},
		{
			in:       []string{"justify-content: center;"},
			expected: []string{"justify-content: center"},
		},
		{
			in:       []string{"left: 150px;"},
			expected: []string{"left: 150px"},
		},
		{
			in:       []string{"letter-spacing: -3px;", "letter-spacing: normal;"},
			expected: []string{"letter-spacing: -3px", "letter-spacing: normal"},
		},
		{
			in:       []string{"line-break: auto"},
			expected: []string{"line-break: auto"},
		},
		{
			in:       []string{"line-height: 1.6;", "line-height: normal;"},
			expected: []string{"line-height: 1.6", "line-height: normal"},
		},
		{
			in: []string{
				"list-style: square inside url(http://sqpurple.gif);",
				"list-style: initial",
			},
			expected: []string{
				"list-style: square inside url(http://sqpurple.gif)",
				"list-style: initial",
			},
		},
		{
			in:       []string{"list-style-image: url(http://sqpurple.gif);"},
			expected: []string{"list-style-image: url(http://sqpurple.gif)"},
		},
		{
			in:       []string{"list-style-position: inside;"},
			expected: []string{"list-style-position: inside"},
		},
		{
			in:       []string{"list-style-type: square;"},
			expected: []string{"list-style-type: square"},
		},
		{
			in:       []string{"margin: 150px;", "margin: auto;"},
			expected: []string{"margin: 150px", "margin: auto"},
		},
		{
			in:       []string{"margin-bottom: 150px;", "margin-bottom: auto;"},
			expected: []string{"margin-bottom: 150px", "margin-bottom: auto"},
		},
		{
			in:       []string{"margin-left: 150px;"},
			expected: []string{"margin-left: 150px"},
		},
		{
			in:       []string{"margin-right: 150px;"},
			expected: []string{"margin-right: 150px"},
		},
		{
			in:       []string{"margin-top: 150px;"},
			expected: []string{"margin-top: 150px"},
		},
		{
			in:       []string{"max-height: 150px;", "max-height: initial;"},
			expected: []string{"max-height: 150px", "max-height: initial"},
		},
		{
			in:       []string{"max-width: 150px;"},
			expected: []string{"max-width: 150px"},
		},
		{
			in:       []string{"min-height: 150px;", "min-height: initial;"},
			expected: []string{"min-height: 150px", "min-height: initial"},
		},
		{
			in:       []string{"min-width: 150px;"},
			expected: []string{"min-width: 150px"},
		},
		{
			in:       []string{"mix-blend-mode: darken;"},
			expected: []string{"mix-blend-mode: darken"},
		},
		{
			in:       []string{"object-fit: cover;"},
			expected: []string{"object-fit: cover"},
		},
		{
			in: []string{
				"object-position: 5px 10%;",
				"object-position: initial",
				"object-position: 5px 10% 5px;",
			},
			expected: []string{
				"object-position: 5px 10%",
				"object-position: initial",
				"",
			},
		},
		{
			in:       []string{"opacity: 0.5;", "opacity: initial"},
			expected: []string{"opacity: 0.5", "opacity: initial"},
		},
		{
			in:       []string{"order: 2;", "order: initial"},
			expected: []string{"order: 2", "order: initial"},
		},
		{
			in:       []string{"outline: 2px dashed blue;", "outline: initial"},
			expected: []string{"outline: 2px dashed blue", "outline: initial"},
		},
		{
			in:       []string{"outline-color: blue;"},
			expected: []string{"outline-color: blue"},
		},
		{
			in:       []string{"outline-offset: 2px;", "outline-offset: initial;"},
			expected: []string{"outline-offset: 2px", "outline-offset: initial"},
		},
		{
			in:       []string{"outline-style: dashed;"},
			expected: []string{"outline-style: dashed"},
		},
		{
			in:       []string{"outline-width: thick;"},
			expected: []string{"outline-width: thick"},
		},
		{
			in:       []string{"overflow: scroll;"},
			expected: []string{"overflow: scroll"},
		},
		{
			in:       []string{"overflow-x: scroll;"},
			expected: []string{"overflow-x: scroll"},
		},
		{
			in:       []string{"overflow-y: scroll;"},
			expected: []string{"overflow-y: scroll"},
		},
		{
			in:       []string{"overflow-wrap: anywhere;"},
			expected: []string{"overflow-wrap: anywhere"},
		},
		{
			in:       []string{"orphans: 2;"},
			expected: []string{"orphans: 2"},
		},
		{
			in:       []string{"padding: 55px;"},
			expected: []string{"padding: 55px"},
		},
		{
			in:       []string{"padding-bottom: 55px;", "padding-bottom: initial;"},
			expected: []string{"padding-bottom: 55px", "padding-bottom: initial"},
		},
		{
			in:       []string{"padding-left: 55px;"},
			expected: []string{"padding-left: 55px"},
		},
		{
			in:       []string{"padding-right: 55px;"},
			expected: []string{"padding-right: 55px"},
		},
		{
			in:       []string{"padding-top: 55px;"},
			expected: []string{"padding-top: 55px"},
		},
		{
			in:       []string{"page-break-after: always;"},
			expected: []string{"page-break-after: always"},
		},
		{
			in:       []string{"page-break-before: always;"},
			expected: []string{"page-break-before: always"},
		},
		{
			in:       []string{"page-break-inside: avoid;"},
			expected: []string{"page-break-inside: avoid"},
		},
		{
			in:       []string{"perspective: 100px;", "perspective: none;"},
			expected: []string{"perspective: 100px", "perspective: none"},
		},
		{
			in:       []string{"perspective-origin: left;"},
			expected: []string{"perspective-origin: left"},
		},
		{
			in:       []string{"pointer-events: auto;"},
			expected: []string{"pointer-events: auto"},
		},
		{
			in:       []string{"position: absolute;"},
			expected: []string{"position: absolute"},
		},
		{
			in:       []string{"quotes: '‹' '›';"},
			expected: []string{"quotes: '‹' '›'"},
		},
		{
			in:       []string{"resize: both;"},
			expected: []string{"resize: both"},
		},
		{
			in:       []string{"right: 10px;"},
			expected: []string{"right: 10px"},
		},
		{
			in:       []string{"scroll-behavior: smooth;"},
			expected: []string{"scroll-behavior: smooth"},
		},
		{
			in:       []string{"tab-size: 16;", "tab-size: initial;"},
			expected: []string{"tab-size: 16", "tab-size: initial"},
		},
		{
			in:       []string{"table-layout: fixed;"},
			expected: []string{"table-layout: fixed"},
		},
		{
			in:       []string{"text-align: justify;"},
			expected: []string{"text-align: justify"},
		},
		{
			in:       []string{"text-align-last: justify;"},
			expected: []string{"text-align-last: justify"},
		},
		{
			in: []string{
				"text-combine-upright: none;",
				"text-combine-upright: digits 2",
			},
			expected: []string{
				"text-combine-upright: none",
				"text-combine-upright: digits 2",
			},
		},
		{
			in: []string{
				"text-decoration: underline underline;",
				"text-decoration: initial",
			},
			expected: []string{
				"text-decoration: underline underline",
				"text-decoration: initial",
			},
		},
		{
			in:       []string{"text-decoration-color: red;"},
			expected: []string{"text-decoration-color: red"},
		},
		{
			in:       []string{"text-decoration-line: underline underline;"},
			expected: []string{"text-decoration-line: underline underline"},
		},
		{
			in:       []string{"text-decoration-style: solid;"},
			expected: []string{"text-decoration-style: solid"},
		},
		{
			in:       []string{"text-indent: 30%;", "text-indent: initial"},
			expected: []string{"text-indent: 30%", "text-indent: initial"},
		},
		{
			in:       []string{"text-orientation: mixed"},
			expected: []string{"text-orientation: mixed"},
		},
		{
			in:       []string{"text-justify: inter-word;"},
			expected: []string{"text-justify: inter-word"},
		},
		{
			in: []string{
				"text-overflow: ellipsis;",
				"text-overflow: 'something'",
			},
			expected: []string{
				"text-overflow: ellipsis",
				"text-overflow: 'something'",
			},
		},
		{
			in:       []string{"text-shadow: 2px 2px #ff0000;"},
			expected: []string{"text-shadow: 2px 2px #ff0000"},
		},
		{
			in:       []string{"text-transform: uppercase;"},
			expected: []string{"text-transform: uppercase"},
		},
		{
			in:       []string{"top: 150px;"},
			expected: []string{"top: 150px"},
		},
		{
			in: []string{
				"transform: scaleY(1.5);",
				"transform: perspective(20px);",
			},
			expected: []string{
				"transform: scaleY(1.5)",
				"transform: perspective(20px)",
			},
		},
		{
			in:       []string{"transform-origin: 40% 40%;"},
			expected: []string{"transform-origin: 40% 40%"},
		},
		{
			in:       []string{"transform-style: preserve-3d;"},
			expected: []string{"transform-style: preserve-3d"},
		},
		{
			in:       []string{"transition: width 2s;"},
			expected: []string{"transition: width 2s"},
		},
		{
			in:       []string{"transition-delay: 2s;", "transition-delay: initial;"},
			expected: []string{"transition-delay: 2s", "transition-delay: initial"},
		},
		{
			in: []string{
				"transition-duration: 2s;",
				"transition-duration: initial;",
			},
			expected: []string{
				"transition-duration: 2s",
				"transition-duration: initial",
			},
		},
		{
			in: []string{
				"transition-property: width;",
				"transition-property: initial;",
			},
			expected: []string{
				"transition-property: width",
				"transition-property: initial",
			},
		},
		{
			in:       []string{"transition-timing-function: linear;"},
			expected: []string{"transition-timing-function: linear"},
		},
		{
			in:       []string{"unicode-bidi: bidi-override;"},
			expected: []string{"unicode-bidi: bidi-override"},
		},
		{
			in:       []string{"user-select: none;"},
			expected: []string{"user-select: none"},
		},
		{
			in:       []string{"vertical-align: text-bottom;"},
			expected: []string{"vertical-align: text-bottom"},
		},
		{
			in:       []string{"visibility: visible;"},
			expected: []string{"visibility: visible"},
		},
		{
			in:       []string{"white-space: normal;"},
			expected: []string{"white-space: normal"},
		},
		{
			in:       []string{"width: 130px;", "width: auto;"},
			expected: []string{"width: 130px", "width: auto"},
		},
		{
			in:       []string{"word-break: break-all;"},
			expected: []string{"word-break: break-all"},
		},
		{
			in:       []string{"word-spacing: 30px;", "word-spacing: normal"},
			expected: []string{"word-spacing: 30px", "word-spacing: normal"},
		},
		{
			in:       []string{"word-wrap: break-word;"},
			expected: []string{"word-wrap: break-word"},
		},
		{
			in:       []string{"writing-mode: vertical-rl;"},
			expected: []string{"writing-mode: vertical-rl"},
		},
		{
			in:       []string{"z-index: -1;", "z-index: auto;"},
			expected: []string{"z-index: -1", "z-index: auto"},
		},
	}

	allStyles := [...]string{
		"nonexistentStyle", "align-content", "align-items",
		"align-self", "all", "animation", "animation-delay",
		"animation-direction", "animation-duration", "animation-fill-mode",
		"animation-iteration-count", "animation-name", "animation-play-state",
		"animation-timing-function", "backface-visibility", "background",
		"background-attachment", "background-blend-mode", "background-clip",
		"background-color", "background-image", "background-origin",
		"background-position", "background-repeat", "background-size",
		"border", "border-bottom", "border-bottom-color",
		"border-bottom-left-radius", "border-bottom-right-radius",
		"border-bottom-style", "border-bottom-width", "border-collapse",
		"border-color", "border-image", "border-image-outset",
		"border-image-repeat", "border-image-slice", "border-image-source",
		"border-image-width", "border-left", "border-left-color",
		"border-left-style", "border-left-width", "border-radius",
		"border-right", "border-right-color", "border-right-style",
		"border-right-width", "border-spacing", "border-style", "border-top",
		"border-top-color", "border-top-left-radius",
		"border-top-right-radius", "border-top-style", "border-top-width",
		"border-width", "bottom", "box-decoration-break", "box-shadow",
		"box-sizing", "break-after", "break-before", "break-inside",
		"caption-side", "caret-color", "clear", "clip", "color",
		"column-count", "column-fill", "column-gap", "column-rule",
		"column-rule-color", "column-rule-style", "column-rule-width",
		"column-span", "column-width", "columns", "cursor", "direction",
		"display", "empty-cells", "filter", "flex", "flex-basis",
		"flex-direction", "flex-flow", "flex-grow", "flex-shrink",
		"flex-wrap", "float", "font", "font-family", "font-kerning",
		"font-language-override", "font-size", "font-size-adjust",
		"font-stretch", "font-style", "font-synthesis", "font-variant",
		"font-variant-caps", "font-variant-position", "font-weight", "grid",
		"grid-area", "grid-auto-columns", "grid-auto-flow", "grid-auto-rows",
		"grid-column", "grid-column-end", "grid-column-gap",
		"grid-column-start", "grid-gap", "grid-row", "grid-row-end",
		"grid-row-gap", "grid-row-start", "grid-template",
		"grid-template-areas", "grid-template-columns", "grid-template-rows",
		"hanging-punctuation", "height", "hyphens", "image-rendering",
		"isolation", "justify-content", "left", "letter-spacing", "line-break",
		"line-height", "list-style", "list-style-image", "list-style-position",
		"list-style-type", "margin", "margin-bottom", "margin-left",
		"margin-right", "margin-top", "max-height", "max-width", "min-height",
		"min-width", "mix-blend-mode", "object-fit", "object-position",
		"opacity", "order", "orphans", "outline", "outline-color",
		"outline-offset", "outline-style", "outline-width", "overflow",
		"overflow-wrap", "overflow-x", "overflow-y", "padding",
		"padding-bottom", "padding-left", "padding-right", "padding-top",
		"page-break-after", "page-break-before", "page-break-inside",
		"perspective", "perspective-origin", "pointer-events", "position",
		"quotes", "resize", "right", "scroll-behavior", "tab-size",
		"table-layout", "text-align", "text-align-last",
		"text-combine-upright", "text-decoration", "text-decoration-color",
		"text-decoration-line", "text-decoration-style", "text-indent",
		"text-justify", "text-orientation", "text-overflow", "text-shadow",
		"text-transform", "top", "transform", "transform-origin",
		"transform-style", "transition", "transition-delay",
		"transition-duration", "transition-property",
		"transition-timing-function", "unicode-bidi", "user-select",
		"vertical-align", "visibility", "white-space", "widows", "width",
		"word-break", "word-spacing", "word-wrap", "writing-mode",
		"z-index",
	}
	p := NewPolicy().AllowStyles(allStyles[:]...).Globally()

	for i, tt := range tests {
		out := make([]string, len(tt.in))
		for i := range tt.in {
			out[i] = p.Sanitize("div", tt.in[i])
		}
		assert.Equal(t, tt.expected, out, "test %v", i)
	}
}

func TestUnicodePoints(t *testing.T) {
	tests := []struct {
		in, expected string
	}{
		{
			in:       `color: \72 ed;`,
			expected: `color: \72 ed`,
		},
		{
			in:       `color: \0072 ed;`,
			expected: `color: \0072 ed`,
		},
		{
			in:       `color: \000072 ed;`,
			expected: `color: \000072 ed`,
		},
		{
			in:       `color: \000072ed;`,
			expected: `color: \000072ed`,
		},
		{
			in: `color: \100072ed;`,
		},
	}

	p := NewPolicy().AllowStyles("color").Globally()
	for i, tt := range tests {
		assert.Equal(t, tt.expected, p.Sanitize("div", tt.in), "test %v", i)
	}
}

func TestMatchingHandler(t *testing.T) {
	tests := []struct {
		in, expected string
	}{
		{
			in:       "color: invalidValue",
			expected: "color: invalidValue",
		},
	}

	p := NewPolicy().AllowStyles("color").MatchingHandler(trueHandler).Globally()
	for i, tt := range tests {
		assert.Equal(t, tt.expected, p.Sanitize("div", tt.in), "test %v", i)
	}
}

func TestAdditivePolicies(t *testing.T) {
	t.Run("AllowStyles", func(t *testing.T) {
		p := NewPolicy()
		p.AllowStyles("color").Matching(regexp.MustCompile("red")).
			OnElements("span")

		t.Run("red", func(t *testing.T) {
			tests := []struct {
				in, expected string
			}{
				{
					in:       "color: red",
					expected: "color: red",
				},
				{
					in: "color: green",
				},
				{
					in: "color: blue",
				},
			}

			for i, tt := range tests {
				assert.Equal(t, tt.expected, p.Sanitize("span", tt.in), "test %v", i)
			}
		})

		p.AllowStyles("color").Matching(regexp.MustCompile("green")).
			OnElements("span")

		t.Run("green", func(t *testing.T) {
			tests := []struct {
				in, expected string
			}{
				{
					in:       "color: red",
					expected: "color: red",
				},
				{
					in:       "color: green",
					expected: "color: green",
				},
				{
					in: "color: blue",
				},
			}

			for i, tt := range tests {
				assert.Equal(t, tt.expected, p.Sanitize("span", tt.in), "test %v", i)
			}
		})

		p.AllowStyles("color").Matching(regexp.MustCompile("yellow")).
			OnElements("span")

		t.Run("yellow", func(t *testing.T) {
			tests := []struct {
				in, expected string
			}{
				{
					in:       "color: red",
					expected: "color: red",
				},
				{
					in:       "color: green",
					expected: "color: green",
				},
				{
					in: "color: blue",
				},
			}

			for i, tt := range tests {
				assert.Equal(t, tt.expected, p.Sanitize("span", tt.in), "test %v", i)
			}
		})
	})
}

func TestIssue171(t *testing.T) {
	// https://github.com/microcosm-cc/bluemonday/issues/171
	//
	// Trailing spaces in the style attribute should not cause the value to be omitted
	p := NewPolicy()
	p.AllowStyles("color", "text-align").OnElements("p")

	assert.Equal(t,
		"color: red; text-align: center",
		p.Sanitize("p", "color: red; text-align: center;   "))
}
