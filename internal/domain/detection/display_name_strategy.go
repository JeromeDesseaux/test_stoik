package detection

import (
	"fmt"
	"strings"

	"github.com/stoik/email-security/internal/domain"
)

// DisplayNameStrategy detects CEO fraud via display name impersonations
type DisplayNameStrategy struct{}

// NewDisplayNameStrategy creates a new display name mismatch detection strategy
func NewDisplayNameStrategy() *DisplayNameStrategy {
	return &DisplayNameStrategy{}
}

// Name returns the strategy name
func (s *DisplayNameStrategy) Name() string {
	return "Display Name Mismatch"
}

// Detect checks if sender display name implies authority but sender email is external
func (s *DisplayNameStrategy) Detect(email domain.Email, recipient *domain.User, context *DetectionContext) *domain.Detection {
	displayName := strings.ToLower(email.SenderName)
	senderDomain := extractDomain(email.SenderEmail)

	// Check if display name contains executive title
	execTitles := []string{"ceo", "cfo", "president", "director", "chief", "vp", "vice president"}
	hasExecTitle := false
	for _, title := range execTitles {
		if strings.Contains(displayName, title) {
			hasExecTitle = true
			break
		}
	}

	// Check if sender domain is external
	isExternal := !isInternalDomain(senderDomain, context.InternalDomains)

	if hasExecTitle && isExternal {
		return &domain.Detection{
			Type:       "DISPLAY_NAME_MISMATCH",
			Confidence: 0.85,
			Evidence: fmt.Sprintf(
				"Display name '%s' contains executive title but sender domain '%s' is external",
				email.SenderName, senderDomain,
			),
		}
	}

	return nil
}
