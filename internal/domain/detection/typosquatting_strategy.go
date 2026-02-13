package detection

import (
	"fmt"

	"github.com/stoik/email-security/internal/domain"
)

// TyposquattingStrategy detects domain typosquatting attacks
type TyposquattingStrategy struct{}

// NewTyposquattingStrategy creates a new domain typosquatting detection strategy
func NewTyposquattingStrategy() *TyposquattingStrategy {
	return &TyposquattingStrategy{}
}

// Name returns the strategy name
func (s *TyposquattingStrategy) Name() string {
	return "Domain Typosquatting"
}

// Detect checks if sender domain is similar to trusted domains
func (s *TyposquattingStrategy) Detect(email domain.Email, recipient *domain.User, context *DetectionContext) *domain.Detection {
	senderDomain := extractDomain(email.SenderEmail)

	for _, trustedDomain := range context.TrustedDomains {
		// Skip if exact match (legitimate email)
		if senderDomain == trustedDomain {
			continue
		}

		// Calculate similarity using Levenshtein distance
		distance := levenshteinDistance(senderDomain, trustedDomain)
		maxLen := float64(max(len(senderDomain), len(trustedDomain)))
		similarity := (1.0 - float64(distance)/maxLen) * 100

		// Flag if very similar but not identical (85% threshold)
		// This threshold is tuned to catch typosquats without false positives
		if similarity > 85 && similarity < 100 {
			return &domain.Detection{
				Type:       "DOMAIN_TYPOSQUATTING",
				Confidence: 0.90,
				Evidence: fmt.Sprintf(
					"Sender domain '%s' is %.1f%% similar to trusted domain '%s' (potential typosquatting)",
					senderDomain, similarity, trustedDomain,
				),
			}
		}
	}

	return nil
}
