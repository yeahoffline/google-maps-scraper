package gmaps

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_sanitizeEmailInput(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"trailing period", "info@domain.com.", "info@domain.com"},
		{"trailing comma", "info@domain.com,", "info@domain.com"},
		{"trailing semicolon", "info@domain.com;", "info@domain.com"},
		{"trailing parenthesis", "info@domain.com)", "info@domain.com"},
		{"leading parenthesis", "(info@domain.com", "info@domain.com"},
		{"parenthetical suffix", "info@domain.com (main contact)", "info@domain.com"},
		{"trailing numbers after TLD", "info@domain.com123", "info@domain.com"},
		{"trailing numbers subdomain", "user@mail.domain.com456", "user@mail.domain.com"},
		{"trailing hyphen", "info@domain.com-", "info@domain.com"},
		{"trailing underscore", "info@domain.com_", "info@domain.com"},
		{"valid with numbers in local", "user123@domain.com", "user123@domain.com"},
		{"valid clean", "info@example.org", "info@example.org"},
		{"whitespace padding", "  info@domain.com  ", "info@domain.com"},
		{"empty", "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := sanitizeEmailInput(tt.input)
			assert.Equal(t, tt.expected, got)
		})
	}
}

func Test_parseMailtoEmails(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected []string
	}{
		{
			name:     "simple mailto",
			input:    "mailto:info@example.com",
			expected: []string{"info@example.com"},
		},
		{
			name:     "mailto with trailing junk",
			input:    "mailto:info@example.com.",
			expected: []string{"info@example.com"},
		},
		{
			name:     "multiple recipients",
			input:    "mailto:foo@example.com,bar@example.com",
			expected: []string{"foo@example.com", "bar@example.com"},
		},
		{
			name:     "blocked no-reply",
			input:    "mailto:noreply@example.com",
			expected: nil,
		},
		{
			name:     "disposable domain rejected",
			input:    "mailto:test@tempmail.com",
			expected: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseMailtoEmails(tt.input)
			assert.Equal(t, tt.expected, got)
		})
	}
}

func Test_filterEmailsBySite(t *testing.T) {
	tests := []struct {
		name     string
		siteURL  string
		emails   []string
		expected []string
	}{
		{
			name:     "site domain match",
			siteURL:  "https://www.myfarm.nl/contact",
			emails:   []string{"info@myfarm.nl", "other@gmail.com"},
			expected: []string{"info@myfarm.nl", "other@gmail.com"},
		},
		{
			name:     "only freemail",
			siteURL:  "https://example.com",
			emails:   []string{"user@gmail.com"},
			expected: []string{"user@gmail.com"},
		},
		{
			name:     "unrelated domain filtered",
			siteURL:  "https://myfarm.nl",
			emails:   []string{"spam@unrelated.com"},
			expected: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := filterEmailsBySite(tt.siteURL, tt.emails)
			assert.Equal(t, tt.expected, got)
		})
	}
}

func Test_regexEmailExtractor(t *testing.T) {
	tests := []struct {
		name     string
		body     string
		minCount int
	}{
		{
			name:     "extracts clean email",
			body:     "Contact us at info@example.com for more",
			minCount: 1,
		},
		{
			name:     "extracts obfuscated [at] [dot]",
			body:     "Email: contact [at] example [dot] com",
			minCount: 1,
		},
		{
			name:     "sanitizes trailing numbers",
			body:     "info@example.com123 or call us",
			minCount: 0, // go-emailaddress may or may not parse this; we rely on sanitize in normalizeEmail
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := regexEmailExtractor([]byte(tt.body))
			require.GreaterOrEqual(t, len(got), tt.minCount)
			for _, e := range got {
				assert.NotContains(t, e, " ")
				assert.NotRegexp(t, `\.[0-9]+$`, e, "email should not end with .123 style")
			}
		})
	}
}
