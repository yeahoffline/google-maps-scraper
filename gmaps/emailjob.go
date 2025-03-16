package gmaps

import (
	"context"
	"fmt"
	"strings"

	"github.com/PuerkitoBio/goquery"
	"github.com/google/uuid"
	"github.com/gosom/google-maps-scraper/exiter"
	"github.com/gosom/scrapemate"
	"github.com/mcnijman/go-emailaddress"
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
			value := strings.TrimPrefix(mailto, "mailto:")
			if email, err := getValidEmail(value); err == nil {
				if !seen[email] {
					emails = append(emails, email)
					seen[email] = true
				}
			}
		}
	})

	// Check text content of elements that commonly contain emails
	doc.Find("p, div, span, address").Each(func(_ int, s *goquery.Selection) {
		text := s.Text()
		if addresses := emailaddress.Find([]byte(text), false); len(addresses) > 0 {
			for _, addr := range addresses {
				email := addr.String()
				if !seen[email] {
					emails = append(emails, email)
					seen[email] = true
				}
			}
		}
	})

	return emails
}

func regexEmailExtractor(body []byte) []string {
	seen := map[string]bool{}
	var emails []string

	// Use more comprehensive regex pattern
	addresses := emailaddress.Find(body, true) // Set strict mode to true
	for i := range addresses {
		email := addresses[i].String()
		if !seen[email] {
			if isValidEmailDomain(email) { // Add domain validation
				emails = append(emails, email)
				seen[email] = true
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
	
	domain := parts[1]
	
	// Skip common disposable email domains
	disposableDomains := map[string]bool{
		// Testing/Example domains
		"example.com":     true,
		"test.com":        true,
		"sample.com":      true,
		
		// Hosting/Website Providers
		"hostgator.com":   true,
		"bluehost.com":    true,
		"godaddy.com":     true,
		"dreamhost.com":   true,
		"hostinger.com":   true,
		"wpengine.com":    true,
		"digitalocean.com": true,
		"aws.amazon.com":  true,
		"azure.com":       true,
		"herokuapp.com":   true,
		"netlify.com":     true,
		"vercel.app":      true,
		"squarespace.com": true,
		"wix.com":         true,
		"wordpress.com":   true,
		"shopify.com":     true,
		
		// Website Builders/CMS
		"weebly.com":      true,
		"webflow.com":     true,
		"myshopify.com":   true,
		"webnode.com":     true,
		"jimdo.com":       true,
		
		// Temporary/Disposable (previous list)
		"tempmail.com":    true,
		"temp-mail.org":   true,
		"guerrillamail.com": true,
		"guerrillamail.net": true,
		"guerrillamail.org": true,
		"sharklasers.com": true,
		"10minutemail.com": true,
		"mailinator.com":  true,
		"maildrop.cc":     true,
		"yopmail.com":     true,
		
		// Common Support/No-Reply Patterns
		"no-reply.com":    true,
		"noreply.com":     true,
		"donotreply.com":  true,
		
		// Common fake/testing
		"localhost":       true,
		"localhost.com":   true,
		"invalid.com":     true,
		"fake.com":        true,
		"notreal.com":     true,
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
	s = strings.ToLower(s) // Normalize to lowercase
	
	// Remove common noise from emails
	s = strings.TrimPrefix(s, "mailto:")
	s = strings.TrimSuffix(s, "?subject=")
	s = strings.Split(s, "?")[0] // Remove any query parameters
	
	email, err := emailaddress.Parse(s)
	if err != nil {
		return "", err
	}

	if !isValidEmailDomain(email.String()) {
		return "", fmt.Errorf("invalid email domain")
	}

	return email.String(), nil
}
