package gmaps

import (
	"bytes"
	"context"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/PuerkitoBio/goquery"
	"github.com/google/uuid"
	"github.com/gosom/google-maps-scraper/exiter"
	"github.com/gosom/scrapemate"
	"github.com/mcnijman/go-emailaddress"
	"golang.org/x/net/publicsuffix"
)

type EmailExtractJobOptions func(*EmailExtractJob)

type EmailExtractJob struct {
	scrapemate.Job

	Entry       *Entry
	ExitMonitor exiter.Exiter
}

func NewEmailJob(parentID string, entry *Entry, opts ...EmailExtractJobOptions) *EmailExtractJob {
	const (
		defaultPrio       = scrapemate.PriorityHigh
		defaultMaxRetries = 0
	)

	job := EmailExtractJob{
		Job: scrapemate.Job{
			ID:         uuid.New().String(),
			ParentID:   parentID,
			Method:     "GET",
			URL:        entry.WebSite,
			MaxRetries: defaultMaxRetries,
			Priority:   defaultPrio,
		},
	}

	job.Entry = entry

	for _, opt := range opts {
		opt(&job)
	}

	return &job
}

func WithEmailJobExitMonitor(exitMonitor exiter.Exiter) EmailExtractJobOptions {
	return func(j *EmailExtractJob) {
		j.ExitMonitor = exitMonitor
	}
}

func (j *EmailExtractJob) Process(ctx context.Context, resp *scrapemate.Response) (any, []scrapemate.IJob, error) {
	defer func() {
		resp.Document = nil
		resp.Body = nil
	}()

	defer func() {
		if j.ExitMonitor != nil {
			j.ExitMonitor.IncrPlacesCompleted(1)
		}
	}()

	log := scrapemate.GetLoggerFromContext(ctx)

	log.Info("Processing email job", "url", j.URL)

	// if html fetch failed just return
	if resp.Error != nil {
		return j.Entry, nil, nil
	}

	doc, ok := resp.Document.(*goquery.Document)
	if !ok {
		return j.Entry, nil, nil
	}

	emails := docEmailExtractor(doc)
	if len(emails) == 0 {
		emails = regexEmailExtractor(resp.Body)
	}

	// Crawl contact/impressum/about pages for additional emails
	contactURLs := findContactPageURLs(doc, j.URL)
	for _, cu := range contactURLs {
		log.Info("Crawling contact page for emails", "url", cu)
		contactEmails := fetchAndExtractEmails(ctx, cu)
		emails = append(emails, contactEmails...)
	}

	emails = deduplicateEmails(emails)

	// Filter emails to those relevant to the site's domain or freemail allowlist
	emails = filterEmailsBySite(j.URL, emails)

	j.Entry.Emails = emails

	return j.Entry, nil, nil
}

func (j *EmailExtractJob) ProcessOnFetchError() bool {
	return true
}

func docEmailExtractor(doc *goquery.Document) []string {
	seen := map[string]bool{}
	var emails []string

	// Check mailto links
	doc.Find("a[href^='mailto:']").Each(func(_ int, s *goquery.Selection) {
		mailto, exists := s.Attr("href")
		if exists {
			for _, e := range parseMailtoEmails(mailto) {
				candidate := normalizeEmail(e)
				if candidate == "" {
					continue
				}
				if !seen[candidate] {
					if isValidEmailDomain(candidate) && !isBlockedLocalPart(candidate) {
						emails = append(emails, candidate)
						seen[candidate] = true
					}
				}
			}
		}
	})

	// Check text content of elements that commonly contain emails
	doc.Find("p, div, span, address, li, td, th, footer, section, header, dd, label, blockquote").Each(func(_ int, s *goquery.Selection) {
		text := s.Text()
		// Light deobfuscation pass before extraction
		deob := deobfuscateEmailsText(text)
		if addresses := emailaddress.Find([]byte(deob), false); len(addresses) > 0 {
			for _, addr := range addresses {
				candidate := normalizeEmail(addr.String())
				if candidate == "" {
					continue
				}
				if !seen[candidate] {
					if isValidEmailDomain(candidate) && !isBlockedLocalPart(candidate) {
						emails = append(emails, candidate)
						seen[candidate] = true
					}
				}
			}
		}
	})

	return emails
}

func regexEmailExtractor(body []byte) []string {
	seen := map[string]bool{}
	var emails []string

	// Apply same deobfuscation to body as a best-effort fallback
	deob := deobfuscateEmailsText(string(body))
	addresses := emailaddress.Find([]byte(deob), false)
	for i := range addresses {
		candidate := normalizeEmail(addresses[i].String())
		if candidate == "" {
			continue
		}
		if !seen[candidate] {
			if isValidEmailDomain(candidate) && !isBlockedLocalPart(candidate) {
				emails = append(emails, candidate)
				seen[candidate] = true
			}
		}
	}

	return emails
}

// New helper function to validate email domains
func isValidEmailDomain(email string) bool {
	parts := strings.Split(email, "@")
	if len(parts) != 2 {
		return false
	}

	domain := strings.ToLower(strings.TrimSpace(parts[1]))

	// Skip common disposable email domains
	disposableDomains := map[string]bool{
		// Testing/Example domains
		"example.com":     true,
		"test.com":        true,
		"sample.com":      true,
		
		// Hosting/Website Providers
		"hostgator.com":    true,
		"bluehost.com":     true,
		"godaddy.com":      true,
		"dreamhost.com":    true,
		"hostinger.com":    true,
		"wpengine.com":     true,
		"digitalocean.com": true,
		"aws.amazon.com":   true,
		"azure.com":        true,
		"herokuapp.com":    true,
		"netlify.com":      true,
		"vercel.app":       true,
		"squarespace.com":  true,
		"wix.com":          true,
		"wordpress.com":    true,
		"shopify.com":      true,
		
		// Website Builders/CMS
		"weebly.com":    true,
		"webflow.com":   true,
		"myshopify.com": true,
		"webnode.com":   true,
		"jimdo.com":     true,
		
		// Temporary/Disposable (previous list)
		"tempmail.com":       true,
		"temp-mail.org":      true,
		"guerrillamail.com":  true,
		"guerrillamail.net":  true,
		"guerrillamail.org":  true,
		"sharklasers.com":    true,
		"10minutemail.com":   true,
		"mailinator.com":     true,
		"maildrop.cc":        true,
		"yopmail.com":        true,
		
		// Common Support/No-Reply Patterns
		"no-reply.com":   true,
		"noreply.com":    true,
		"donotreply.com": true,
		
		// Common fake/testing
		"localhost":     true,
		"localhost.com": true,
		"invalid.com":   true,
		"fake.com":      true,
		"notreal.com":   true,
	}

	if disposableDomains[domain] {
		return false
	}

	// Basic domain validation
	if !strings.Contains(domain, ".") {
		return false
	}

	return true
}

func getValidEmail(s string) (string, error) {
	s = strings.TrimSpace(s)
	s = strings.ToLower(s)

	// Remove common noise from emails
	s = strings.TrimPrefix(s, "mailto:")
	s = sanitizeEmailInput(s)
	// Remove any query parameters
	if idx := strings.IndexByte(s, '?'); idx >= 0 {
		s = s[:idx]
	}

	// Unescape percent-encoded sequences (handle both query and path styles)
	if u, err := url.QueryUnescape(s); err == nil {
		s = u
	} else if u2, err2 := url.PathUnescape(s); err2 == nil {
		s = u2
	}

	email, err := emailaddress.Parse(s)
	if err != nil {
		return "", err
	}

	if !isValidEmailDomain(email.String()) {
		return "", fmt.Errorf("invalid email domain")
	}

	return email.String(), nil
}

// normalizeEmail lowercases, trims, and sanitizes an email string
func normalizeEmail(s string) string {
	s = strings.TrimSpace(strings.ToLower(s))
	if s == "" {
		return ""
	}
	return sanitizeEmailInput(s)
}

// sanitizeEmailInput removes common junk (trailing punctuation, numbers, parentheticals) from email candidates
func sanitizeEmailInput(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	// Strip leading/trailing punctuation and whitespace
	trimChars := ".,;:!?()[]{}\"' \t\n\r"
	s = strings.Trim(s, trimChars)
	// Remove parenthetical suffix: "email@domain.com (contact)" -> "email@domain.com"
	if idx := strings.Index(s, " ("); idx > 0 {
		s = strings.TrimSpace(s[:idx])
		s = strings.Trim(s, trimChars)
	}
	// Remove trailing numbers after what looks like a valid email (e.g. "info@domain.com123" -> "info@domain.com")
	if trailingNums := regexp.MustCompile(`^([a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,})[0-9]+$`); trailingNums.MatchString(s) {
		s = trailingNums.ReplaceAllString(s, "$1")
	}
	// Remove trailing hyphen or underscore that sometimes gets captured
	s = strings.TrimRight(s, "-_")
	return s
}

// parseMailtoEmails parses a mailto: link and returns zero or more valid emails
func parseMailtoEmails(mailto string) []string {
	var result []string
	s := strings.TrimSpace(strings.ToLower(mailto))
	if !strings.HasPrefix(s, "mailto:") {
		// Not a mailto, treat whole string as a single email
		if e, err := getValidEmail(s); err == nil {
			if isValidEmailDomain(e) && !isBlockedLocalPart(e) {
				result = append(result, e)
			}
		}
		return result
	}
	s = strings.TrimPrefix(s, "mailto:")
	// split off params
	if idx := strings.IndexByte(s, '?'); idx >= 0 {
		s = s[:idx]
	}
	// unescape
	if u, err := url.QueryUnescape(s); err == nil {
		s = u
	} else if u2, err2 := url.PathUnescape(s); err2 == nil {
		s = u2
	}
	// support multiple recipients separated by comma/semicolon
	parts := splitRecipients(s)
	seen := map[string]bool{}
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if e, err := getValidEmail(part); err == nil {
			e = normalizeEmail(e)
			if e != "" && isValidEmailDomain(e) && !isBlockedLocalPart(e) && !seen[e] {
				result = append(result, e)
				seen[e] = true
			}
		}
	}
	return result
}

func splitRecipients(s string) []string {
	// split on comma and semicolon
	return regexp.MustCompile(`[;,]`).Split(s, -1)
}

// isBlockedLocalPart filters common no-reply style addresses
func isBlockedLocalPart(email string) bool {
	parts := strings.Split(email, "@")
	if len(parts) != 2 {
		return true
	}
	local := strings.ToLower(parts[0])
	patterns := []string{
		`^no[\-\._]?reply$`,
		`^do[\-\._]?not[\-\._]?reply$`,
		`^donotreply$`,
	}
	for _, p := range patterns {
		if regexp.MustCompile(p).MatchString(local) {
			return true
		}
	}
	return false
}

// deobfuscateEmailsText replaces common obfuscations like "[at]", "[dot]", and HTML entities
func deobfuscateEmailsText(s string) string {
	// Decode HTML entities first (&#64; → @, &#46; → ., &#x40; → @, etc.)
	r := html.UnescapeString(s)
	r = strings.ToLower(r)
	// Replace bracketed and spaced variants
	replacements := []struct{ re, sub string }{
		{re: `\s*\[\s*at\s*\]\s*|\s*\(\s*at\s*\)\s*|\s*\{\s*at\s*\}\s*`, sub: "@"},
		{re: `\s*\[\s*dot\s*\]\s*|\s*\(\s*dot\s*\)\s*|\s*\{\s*dot\s*\}\s*`, sub: "."},
		{re: `\s*\[\s*d0t\s*\]\s*|\s*\(\s*d0t\s*\)\s*|\s*\{\s*d0t\s*\}\s*`, sub: "."},
	}
	out := r
	for _, rp := range replacements {
		out = regexp.MustCompile(rp.re).ReplaceAllString(out, rp.sub)
	}
	// Remove spaces around @ only (not dots -- global dot-space removal creates false positives)
	out = regexp.MustCompile(`\s*@\s*`).ReplaceAllString(out, "@")
	return out
}

// getRegistrableDomain returns the eTLD+1 for a given hostname
func getRegistrableDomain(host string) string {
	host = strings.ToLower(strings.TrimSpace(host))
	if host == "" {
		return ""
	}
	if strings.Contains(host, "://") {
		if u, err := url.Parse(host); err == nil {
			host = u.Hostname()
		}
	}
	d, err := publicsuffix.EffectiveTLDPlusOne(host)
	if err != nil {
		return host
	}
	return d
}

// filterEmailsBySite keeps emails that belong to the site's registrable domain or freemail allowlist
func filterEmailsBySite(siteURL string, emails []string) []string {
	if len(emails) == 0 {
		return emails
	}
	regDomain := getRegistrableDomain(siteURL)
	allowFreemail := map[string]bool{
		"googlemail.com": true,
		"gmail.com":      true,
		"yahoo.com":      true,
		"yahoo.nl":       true,
		"outlook.com":    true,
		"outlook.nl":     true,
		"hotmail.com":    true,
		"hotmail.nl":     true,
		"live.com":       true,
		"live.nl":        true,
		"msn.com":        true,
		"icloud.com":     true,
		"proton.me":      true,
		"pm.me":          true,
		"t-online.de":    true,
		"t-online.at":    true,
		"freenet.de":     true,
		"gmx.de":         true,
		"gmx.net":        true,
		"gmx.com":        true,
		"gmx.ch":         true,
		"gmx.at":         true,
		"gmx.eu":         true,
		"gmx.fr":         true,
		"gmx.it":         true,
		"gmx.es":         true,
		"gmx.nl":         true,
		"gmx.pt":         true,
		"web.de":         true,
		"ziggo.nl":       true,
		"kpnmail.nl":     true,
		"kpnplanet.nl":   true,
		"hetnet.nl":      true,
		"home.nl":        true,
		"planet.nl":      true,
		"xs4all.nl":      true,
		"upcmail.nl":     true,
		"casema.nl":      true,
		"chello.nl":      true,
		"quicknet.nl":    true,
		"solcon.nl":      true,
		"tele2.nl":       true,
	}
	var out []string
	seen := map[string]bool{}
	for _, e := range emails {
		parts := strings.Split(strings.ToLower(strings.TrimSpace(e)), "@")
		if len(parts) != 2 {
			continue
		}
		domain := parts[1]
		rd := getRegistrableDomain(domain)
		if allowFreemail[rd] || (regDomain != "" && rd == regDomain) {
			if !seen[e] {
				out = append(out, e)
				seen[e] = true
			}
		}
	}
	return out
}

var contactPagePatterns = []string{
	"contact", "kontakt", "impressum", "imprint", "about",
	"over-ons", "about-us", "contact-us", "ueber-uns",
	"over ons", "neem contact", "kontaktieren",
}

const maxContactPages = 5

// findContactPageURLs finds links to contact/impressum/about pages in the document
func findContactPageURLs(doc *goquery.Document, baseURL string) []string {
	base, err := url.Parse(baseURL)
	if err != nil {
		return nil
	}

	seen := map[string]bool{base.String(): true}
	var urls []string

	doc.Find("a[href]").Each(func(_ int, s *goquery.Selection) {
		if len(urls) >= maxContactPages {
			return
		}

		href, exists := s.Attr("href")
		if !exists || href == "" || strings.HasPrefix(href, "#") || strings.HasPrefix(href, "javascript:") {
			return
		}

		text := strings.ToLower(strings.TrimSpace(s.Text()))
		hrefLower := strings.ToLower(href)

		isContact := false
		for _, p := range contactPagePatterns {
			if strings.Contains(hrefLower, p) || strings.Contains(text, p) {
				isContact = true
				break
			}
		}

		if !isContact {
			return
		}

		resolved, err := base.Parse(href)
		if err != nil {
			return
		}

		// Only follow same-host links
		if resolved.Host != "" && resolved.Host != base.Host {
			return
		}

		fullURL := resolved.String()
		if !seen[fullURL] {
			urls = append(urls, fullURL)
			seen[fullURL] = true
		}
	})

	return urls
}

// fetchAndExtractEmails fetches a page and extracts emails from it
func fetchAndExtractEmails(ctx context.Context, pageURL string) []string {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", pageURL, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
	req.Header.Set("Accept", "text/html,application/xhtml+xml")

	client := &http.Client{
		Timeout: 15 * time.Second,
		CheckRedirect: func(_ *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil
	}

	const maxBodySize = 5 << 20 // 5 MB
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBodySize))
	if err != nil {
		return nil
	}

	doc, err := goquery.NewDocumentFromReader(bytes.NewReader(body))
	if err != nil {
		return nil
	}

	emails := docEmailExtractor(doc)
	if len(emails) == 0 {
		emails = regexEmailExtractor(body)
	}

	return emails
}

func deduplicateEmails(emails []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, e := range emails {
		e = strings.ToLower(strings.TrimSpace(e))
		if e != "" && !seen[e] {
			out = append(out, e)
			seen[e] = true
		}
	}
	return out
}

// checkSolarKeywords checks if the website content contains any solar-related keywords
func checkSolarKeywords(doc *goquery.Document, body []byte) bool {
	solarKeywords := []string{
		"Solar",
		"Investitionsbzugsbetrag",
		"Photovoltaik",
	}

	// Check in document text
	text := doc.Text()
	for _, keyword := range solarKeywords {
		if strings.Contains(text, keyword) {
			return true
		}
	}

	// Also check in raw body as fallback
	bodyStr := strings.ToLower(string(body))
	for _, keyword := range solarKeywords {
		if strings.Contains(bodyStr, strings.ToLower(keyword)) {
			return true
		}
	}

	return false
}