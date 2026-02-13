package detection

import (
	"fmt"
	"strings"

	"github.com/stoik/email-security/internal/domain"
)

// AuthFailuresStrategy detects email authentication failures
//
// Email authentication standards (SPF, DKIM, DMARC) verify that emails are legitimately
// sent from the claimed domain. When these checks fail, it indicates potential spoofing.
type AuthFailuresStrategy struct{}

// NewAuthFailuresStrategy creates a new email authentication failures detection strategy
func NewAuthFailuresStrategy() *AuthFailuresStrategy {
	return &AuthFailuresStrategy{}
}

// Name returns the strategy name
func (s *AuthFailuresStrategy) Name() string {
	return "Authentication Failures"
}

// Detect checks email headers for SPF, DKIM, DMARC failures
func (s *AuthFailuresStrategy) Detect(email domain.Email, recipient *domain.User, context *DetectionContext) *domain.Detection {
	failures := make([]string, 0)

	// Check SPF (Sender Policy Framework)
	// SPF verifies that sending server is authorized by domain owner
	if spf, ok := email.Headers["Received-SPF"]; ok {
		if strings.Contains(strings.ToLower(spf), "fail") {
			failures = append(failures, "SPF_FAIL")
		}
	}

	// Check DKIM (DomainKeys Identified Mail)
	// DKIM uses cryptographic signatures to verify email hasn't been tampered with
	if authResults, ok := email.Headers["Authentication-Results"]; ok {
		if strings.Contains(strings.ToLower(authResults), "dkim=fail") {
			failures = append(failures, "DKIM_FAIL")
		}

		// Check DMARC (Domain-based Message Authentication, Reporting & Conformance)
		// DMARC builds on SPF and DKIM to prevent domain spoofing
		if strings.Contains(strings.ToLower(authResults), "dmarc=fail") {
			failures = append(failures, "DMARC_FAIL")
		}
	}

	// Multiple failures = high confidence of spoofing
	// Rationale: legitimate misconfigurations usually affect only one protocol
	if len(failures) >= 2 {
		return &domain.Detection{
			Type:       "AUTH_FAILURES",
			Confidence: 0.80,
			Evidence:   fmt.Sprintf("Email authentication failures: %s", strings.Join(failures, ", ")),
		}
	}

	return nil
}
