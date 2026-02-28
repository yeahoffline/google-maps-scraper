package gmaps

import (
	"strings"
	"testing"

	"github.com/PuerkitoBio/goquery"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- sanitizeEmailInput ---

func Test_sanitizeEmailInput(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"clean email", "info@domain.com", "info@domain.com"},
		{"trailing period", "info@domain.com.", "info@domain.com"},
		{"trailing comma", "info@domain.com,", "info@domain.com"},
		{"trailing semicolon", "info@domain.com;", "info@domain.com"},
		{"trailing exclamation", "info@domain.com!", "info@domain.com"},
		{"trailing parenthesis", "info@domain.com)", "info@domain.com"},
		{"leading parenthesis", "(info@domain.com", "info@domain.com"},
		{"wrapped in parens", "(info@domain.com)", "info@domain.com"},
		{"wrapped in brackets", "[info@domain.com]", "info@domain.com"},
		{"parenthetical suffix", "info@domain.com (main contact)", "info@domain.com"},
		{"trailing numbers after TLD", "info@domain.com123", "info@domain.com"},
		{"trailing numbers after subdomain TLD", "user@mail.domain.com456", "user@mail.domain.com"},
		{"trailing hyphen", "info@domain.com-", "info@domain.com"},
		{"trailing underscore", "info@domain.com_", "info@domain.com"},
		{"numbers in local part preserved", "user123@domain.com", "user123@domain.com"},
		{"plus in local part preserved", "user+tag@domain.com", "user+tag@domain.com"},
		{"whitespace padding", "  info@domain.com  ", "info@domain.com"},
		{"empty", "", ""},
		{"quoted email", "'info@domain.com'", "info@domain.com"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := sanitizeEmailInput(tt.input)
			assert.Equal(t, tt.expected, got)
		})
	}
}

// --- normalizeEmail ---

func Test_normalizeEmail(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"lowercase", "INFO@Domain.COM", "info@domain.com"},
		{"trim and lower", "  User@Example.Org  ", "user@example.org"},
		{"trailing junk removed", "INFO@DOMAIN.COM.", "info@domain.com"},
		{"empty", "", ""},
		{"whitespace only", "   ", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := normalizeEmail(tt.input)
			assert.Equal(t, tt.expected, got)
		})
	}
}

// --- isValidEmailDomain ---

func Test_isValidEmailDomain(t *testing.T) {
	tests := []struct {
		name     string
		email    string
		expected bool
	}{
		{"valid domain", "info@myfarm.nl", true},
		{"valid subdomain", "info@mail.myfarm.nl", true},
		{"example.com blocked", "test@example.com", false},
		{"tempmail.com blocked", "user@tempmail.com", false},
		{"mailinator.com blocked", "user@mailinator.com", false},
		{"localhost blocked", "user@localhost", false},
		{"no dot in domain", "user@localdomain", false},
		{"wix.com blocked", "user@wix.com", false},
		{"wordpress.com blocked", "user@wordpress.com", false},
		{"valid gmail", "user@gmail.com", true},
		{"valid custom", "info@boerderij.nl", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isValidEmailDomain(tt.email)
			assert.Equal(t, tt.expected, got)
		})
	}
}

// --- isBlockedLocalPart ---

func Test_isBlockedLocalPart(t *testing.T) {
	tests := []struct {
		name     string
		email    string
		expected bool
	}{
		{"noreply", "noreply@domain.com", true},
		{"no-reply", "no-reply@domain.com", true},
		{"no_reply", "no_reply@domain.com", true},
		{"no.reply", "no.reply@domain.com", true},
		{"donotreply", "donotreply@domain.com", true},
		{"do-not-reply", "do-not-reply@domain.com", true},
		{"do_not_reply", "do_not_reply@domain.com", true},
		{"info is valid", "info@domain.com", false},
		{"contact is valid", "contact@domain.com", false},
		{"admin is valid", "admin@domain.com", false},
		{"invalid no @", "noreply", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isBlockedLocalPart(tt.email)
			assert.Equal(t, tt.expected, got)
		})
	}
}

// --- deobfuscateEmailsText ---

func Test_deobfuscateEmailsText(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		contains string
	}{
		{"bracket at", "info [at] domain [dot] com", "info@domain.com"},
		{"paren at", "info (at) domain (dot) com", "info@domain.com"},
		{"curly at", "info {at} domain {dot} com", "info@domain.com"},
		{"d0t variant", "info [at] domain [d0t] com", "info@domain.com"},
		{"spaced @", "info @ domain.com", "info@domain.com"},
		{"HTML entity at", "info&#64;domain.com", "info@domain.com"},
		{"HTML hex entity at", "info&#x40;domain.com", "info@domain.com"},
		{"HTML entity dot", "info@domain&#46;com", "info@domain.com"},
		{"normal email unchanged", "info@domain.com", "info@domain.com"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := deobfuscateEmailsText(tt.input)
			assert.Contains(t, got, tt.contains)
		})
	}
}

func Test_deobfuscateEmailsText_no_false_positives(t *testing.T) {
	input := "Dr. Smith visited on Jan. 5th. The price is $10.00."
	got := deobfuscateEmailsText(input)
	assert.NotContains(t, got, "@", "should not create @ from normal text")
}

// --- parseMailtoEmails ---

func Test_parseMailtoEmails(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected []string
	}{
		{
			name:     "simple mailto",
			input:    "mailto:info@example.org",
			expected: []string{"info@example.org"},
		},
		{
			name:     "mailto with trailing period",
			input:    "mailto:info@example.org.",
			expected: []string{"info@example.org"},
		},
		{
			name:     "mailto with query params",
			input:    "mailto:info@example.org?subject=Hello",
			expected: []string{"info@example.org"},
		},
		{
			name:     "multiple recipients comma",
			input:    "mailto:foo@example.org,bar@example.org",
			expected: []string{"foo@example.org", "bar@example.org"},
		},
		{
			name:     "multiple recipients semicolon",
			input:    "mailto:foo@example.org;bar@example.org",
			expected: []string{"foo@example.org", "bar@example.org"},
		},
		{
			name:     "percent-encoded @",
			input:    "mailto:info%40example.org",
			expected: []string{"info@example.org"},
		},
		{
			name:     "blocked no-reply",
			input:    "mailto:noreply@example.org",
			expected: nil,
		},
		{
			name:     "disposable domain rejected",
			input:    "mailto:test@tempmail.com",
			expected: nil,
		},
		{
			name:     "deduplicates same email",
			input:    "mailto:info@example.org,info@example.org",
			expected: []string{"info@example.org"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseMailtoEmails(tt.input)
			assert.Equal(t, tt.expected, got)
		})
	}
}

// --- getValidEmail ---

func Test_getValidEmail(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		{"valid", "info@example.org", "info@example.org", false},
		{"uppercase normalized", "INFO@Example.Org", "info@example.org", false},
		{"with mailto prefix", "mailto:info@example.org", "info@example.org", false},
		{"with query params", "info@example.org?subject=hi", "info@example.org", false},
		{"trailing period", "info@example.org.", "info@example.org", false},
		{"disposable domain", "info@tempmail.com", "", true},
		{"garbage", "notanemail", "", true},
		{"empty", "", "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := getValidEmail(tt.input)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.want, got)
			}
		})
	}
}

// --- filterEmailsBySite ---

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
			name:     "subdomain match via registrable domain",
			siteURL:  "https://www.myfarm.nl",
			emails:   []string{"info@mail.myfarm.nl"},
			expected: []string{"info@mail.myfarm.nl"},
		},
		{
			name:     "only freemail gmail",
			siteURL:  "https://somesite.com",
			emails:   []string{"user@gmail.com"},
			expected: []string{"user@gmail.com"},
		},
		{
			name:     "NL freemail ziggo",
			siteURL:  "https://somesite.nl",
			emails:   []string{"user@ziggo.nl"},
			expected: []string{"user@ziggo.nl"},
		},
		{
			name:     "NL freemail kpnmail",
			siteURL:  "https://somesite.nl",
			emails:   []string{"user@kpnmail.nl"},
			expected: []string{"user@kpnmail.nl"},
		},
		{
			name:     "NL freemail hetnet",
			siteURL:  "https://somesite.nl",
			emails:   []string{"user@hetnet.nl"},
			expected: []string{"user@hetnet.nl"},
		},
		{
			name:     "unrelated domain filtered",
			siteURL:  "https://myfarm.nl",
			emails:   []string{"spam@unrelated.com"},
			expected: nil,
		},
		{
			name:     "evil subdomain attack blocked",
			siteURL:  "https://myfarm.nl",
			emails:   []string{"info@evil-myfarm.nl"},
			expected: nil,
		},
		{
			name:     "empty emails",
			siteURL:  "https://myfarm.nl",
			emails:   []string{},
			expected: []string{},
		},
		{
			name:     "deduplicates",
			siteURL:  "https://myfarm.nl",
			emails:   []string{"info@myfarm.nl", "info@myfarm.nl"},
			expected: []string{"info@myfarm.nl"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := filterEmailsBySite(tt.siteURL, tt.emails)
			assert.Equal(t, tt.expected, got)
		})
	}
}

// --- deduplicateEmails ---

func Test_deduplicateEmails(t *testing.T) {
	tests := []struct {
		name     string
		input    []string
		expected []string
	}{
		{
			name:     "no duplicates",
			input:    []string{"a@b.com", "c@d.com"},
			expected: []string{"a@b.com", "c@d.com"},
		},
		{
			name:     "removes duplicates",
			input:    []string{"a@b.com", "a@b.com", "c@d.com"},
			expected: []string{"a@b.com", "c@d.com"},
		},
		{
			name:     "case insensitive dedup",
			input:    []string{"Info@Domain.com", "info@domain.com"},
			expected: []string{"info@domain.com"},
		},
		{
			name:     "empty input",
			input:    []string{},
			expected: nil,
		},
		{
			name:     "nil input",
			input:    nil,
			expected: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := deduplicateEmails(tt.input)
			assert.Equal(t, tt.expected, got)
		})
	}
}

// --- getRegistrableDomain ---

func Test_getRegistrableDomain(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"simple domain", "myfarm.nl", "myfarm.nl"},
		{"with subdomain", "www.myfarm.nl", "myfarm.nl"},
		{"full URL", "https://www.myfarm.nl/contact", "myfarm.nl"},
		{"co.uk domain", "www.example.co.uk", "example.co.uk"},
		{"empty", "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := getRegistrableDomain(tt.input)
			assert.Equal(t, tt.expected, got)
		})
	}
}

// --- docEmailExtractor ---

func Test_docEmailExtractor(t *testing.T) {
	tests := []struct {
		name      string
		html      string
		expected  []string
		minCount  int
	}{
		{
			name: "mailto link",
			html: `<html><body><a href="mailto:info@myfarm.nl">Email us</a></body></html>`,
			expected: []string{"info@myfarm.nl"},
		},
		{
			name: "email in paragraph",
			html: `<html><body><p>Contact: info@myfarm.nl</p></body></html>`,
			expected: []string{"info@myfarm.nl"},
		},
		{
			name: "email in footer",
			html: `<html><body><footer>info@myfarm.nl</footer></body></html>`,
			expected: []string{"info@myfarm.nl"},
		},
		{
			name: "email in list item",
			html: `<html><body><ul><li>info@myfarm.nl</li></ul></body></html>`,
			expected: []string{"info@myfarm.nl"},
		},
		{
			name: "email in table cell",
			html: `<html><body><table><tr><td>info@myfarm.nl</td></tr></table></body></html>`,
			expected: []string{"info@myfarm.nl"},
		},
		{
			name: "obfuscated with [at] [dot]",
			html: `<html><body><p>info [at] myfarm [dot] nl</p></body></html>`,
			expected: []string{"info@myfarm.nl"},
		},
		{
			name: "noreply filtered",
			html: `<html><body><a href="mailto:noreply@myfarm.nl">No reply</a></body></html>`,
			expected: nil,
		},
		{
			name: "multiple emails deduped",
			html: `<html><body>
				<a href="mailto:info@myfarm.nl">Email</a>
				<p>info@myfarm.nl</p>
			</body></html>`,
			expected: []string{"info@myfarm.nl"},
		},
		{
			name: "email in section",
			html: `<html><body><section>info@myfarm.nl</section></body></html>`,
			expected: []string{"info@myfarm.nl"},
		},
		{
			name:     "no emails",
			html:     `<html><body><p>No email here</p></body></html>`,
			expected: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			doc, err := goquery.NewDocumentFromReader(strings.NewReader(tt.html))
			require.NoError(t, err)
			got := docEmailExtractor(doc)
			if tt.expected != nil {
				assert.Equal(t, tt.expected, got)
			} else {
				assert.Empty(t, got)
			}
		})
	}
}

// --- regexEmailExtractor ---

func Test_regexEmailExtractor(t *testing.T) {
	tests := []struct {
		name     string
		body     string
		expected []string
	}{
		{
			name:     "extracts clean email",
			body:     "Contact us at info@example.org for more",
			expected: []string{"info@example.org"},
		},
		{
			name:     "extracts obfuscated [at] [dot]",
			body:     "Email: contact [at] example [dot] org",
			expected: []string{"contact@example.org"},
		},
		{
			name:     "filters disposable domain",
			body:     "Email: test@tempmail.com",
			expected: nil,
		},
		{
			name:     "filters noreply",
			body:     "noreply@example.org",
			expected: nil,
		},
		{
			name:     "multiple emails",
			body:     "a@example.org and b@example.org",
			expected: []string{"a@example.org", "b@example.org"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := regexEmailExtractor([]byte(tt.body))
			if tt.expected != nil {
				assert.Equal(t, tt.expected, got)
			} else {
				assert.Empty(t, got)
			}
		})
	}
}

// --- findContactPageURLs ---

func Test_findContactPageURLs(t *testing.T) {
	tests := []struct {
		name     string
		html     string
		baseURL  string
		expected []string
	}{
		{
			name:     "finds contact link",
			html:     `<html><body><a href="/contact">Contact</a></body></html>`,
			baseURL:  "https://www.myfarm.nl",
			expected: []string{"https://www.myfarm.nl/contact"},
		},
		{
			name:     "finds impressum link",
			html:     `<html><body><a href="/impressum">Impressum</a></body></html>`,
			baseURL:  "https://www.bauernhof.de",
			expected: []string{"https://www.bauernhof.de/impressum"},
		},
		{
			name:     "finds over-ons link",
			html:     `<html><body><a href="/over-ons">Over ons</a></body></html>`,
			baseURL:  "https://www.myfarm.nl",
			expected: []string{"https://www.myfarm.nl/over-ons"},
		},
		{
			name: "finds by link text",
			html: `<html><body><a href="/pagina5">Contact</a></body></html>`,
			baseURL:  "https://www.myfarm.nl",
			expected: []string{"https://www.myfarm.nl/pagina5"},
		},
		{
			name:     "skips external links",
			html:     `<html><body><a href="https://other.com/contact">Contact</a></body></html>`,
			baseURL:  "https://www.myfarm.nl",
			expected: nil,
		},
		{
			name:     "skips javascript links",
			html:     `<html><body><a href="javascript:void(0)">Contact</a></body></html>`,
			baseURL:  "https://www.myfarm.nl",
			expected: nil,
		},
		{
			name:     "skips anchor links",
			html:     `<html><body><a href="#contact">Contact</a></body></html>`,
			baseURL:  "https://www.myfarm.nl",
			expected: nil,
		},
		{
			name:     "deduplicates same URL",
			html:     `<html><body><a href="/contact">Contact</a><a href="/contact">Email us</a></body></html>`,
			baseURL:  "https://www.myfarm.nl",
			expected: []string{"https://www.myfarm.nl/contact"},
		},
		{
			name:     "no contact links",
			html:     `<html><body><a href="/products">Products</a></body></html>`,
			baseURL:  "https://www.myfarm.nl",
			expected: nil,
		},
		{
			name: "skips base URL itself",
			html: `<html><body><a href="https://www.myfarm.nl">Contact us</a></body></html>`,
			baseURL:  "https://www.myfarm.nl",
			expected: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			doc, err := goquery.NewDocumentFromReader(strings.NewReader(tt.html))
			require.NoError(t, err)
			got := findContactPageURLs(doc, tt.baseURL)
			if tt.expected != nil {
				assert.Equal(t, tt.expected, got)
			} else {
				assert.Empty(t, got)
			}
		})
	}
}

// --- splitRecipients ---

func Test_splitRecipients(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected []string
	}{
		{"comma", "a@b.com,c@d.com", []string{"a@b.com", "c@d.com"}},
		{"semicolon", "a@b.com;c@d.com", []string{"a@b.com", "c@d.com"}},
		{"mixed", "a@b.com,c@d.com;e@f.com", []string{"a@b.com", "c@d.com", "e@f.com"}},
		{"single", "a@b.com", []string{"a@b.com"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := splitRecipients(tt.input)
			assert.Equal(t, tt.expected, got)
		})
	}
}
