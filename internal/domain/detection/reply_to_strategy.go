package detection

import (
	"fmt"
	"strings"

	"github.com/stoik/email-security/internal/domain"
)

// ReplyToStrategy detects Reply-To header mismatches
type ReplyToStrategy struct{}

// NewReplyToStrategy creates a new Reply-To mismatch detection strategy
func NewReplyToStrategy() *ReplyToStrategy {
	return &ReplyToStrategy{}
}

// Name returns the strategy name
func (s *ReplyToStrategy) Name() string {
	return "Reply-To Mismatch"
}

// Detect checks if Reply-To header differs from sender and redirects to free email
func (s *ReplyToStrategy) Detect(email domain.Email, recipient *domain.User, context *DetectionContext) *domain.Detection {
	senderEmail := strings.ToLower(email.SenderEmail)
	replyTo := strings.ToLower(email.Headers["Reply-To"])

	// If Reply-To is empty or same as sender, no issue
	if replyTo == "" || replyTo == senderEmail {
		return nil
	}

	senderDomain := extractDomain(senderEmail)
	replyToDomain := extractDomain(replyTo)

	// Check if Reply-To redirects to free email service
	freeEmailDomains := []string{"gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "aol.com"}
	isFreemail := false
	for _, freeDomain := range freeEmailDomains {
		if replyToDomain == freeDomain {
			isFreemail = true
			break
		}
	}

	// Suspicious if reply-to is freemail and different from sender
	// This is a strong indicator of phishing/BEC attack
	if isFreemail && replyToDomain != senderDomain {
		return &domain.Detection{
			Type:       "REPLY_TO_MISMATCH",
			Confidence: 0.75,
			Evidence: fmt.Sprintf(
				"Sender: %s, Reply-To: %s (free email service, redirects responses)",
				senderEmail, replyTo,
			),
		}
	}

	return nil
}
