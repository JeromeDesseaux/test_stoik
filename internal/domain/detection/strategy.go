package detection

import (
	"github.com/stoik/email-security/internal/domain"
)

// DetectionStrategy defines the interface that all fraud detection strategies must implement
//
// This follows the Strategy pattern, allowing each detection technique to be:
//   - Independently developed and tested
//   - Easily added or removed from the detection pipeline
//   - Configured with different weights and thresholds
type DetectionStrategy interface {
	// Detect analyzes an email and returns a Detection if a threat is found, nil otherwise
	Detect(email domain.Email, recipient *domain.User, context *DetectionContext) *domain.Detection

	// Name returns the human-readable name of this detection strategy
	Name() string
}

// DetectionContext provides shared context needed by multiple detection strategies
type DetectionContext struct {
	// InternalDomains are the organization's own domains (e.g., "company.com")
	// Used to distinguish internal vs external senders
	InternalDomains []string

	// TrustedDomains are legitimate external domains (e.g., "microsoft.com", "paypal.com")
	// Used for typosquatting detection
	TrustedDomains []string
}

// NewDetectionContext creates a new detection context with the provided configuration
func NewDetectionContext(internalDomains, trustedDomains []string) *DetectionContext {
	return &DetectionContext{
		InternalDomains: internalDomains,
		TrustedDomains:  trustedDomains,
	}
}
