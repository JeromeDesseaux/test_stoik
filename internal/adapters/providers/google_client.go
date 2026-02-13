package providers

import (
	"context"
	"log"
	"net/mail"
	"time"

	"github.com/google/uuid"
	"github.com/stoik/email-security/internal/domain"
)

// GoogleClient implements ports.EmailProvider for Gmail API
// For this prototype: returns mock data to demonstrate the pipeline
type GoogleClient struct{}

// NewGoogleClient creates a new client
func NewGoogleClient() *GoogleClient {
	return &GoogleClient{}
}

// GetUsers fetches all users for a tenant from Google Workspace Directory API
func (c *GoogleClient) GetUsers(ctx context.Context, tenantID uuid.UUID) ([]domain.User, error) {
	// Mock implementation - returns sample users

	users := []domain.User{
		{
			ID:             uuid.New(),
			TenantID:       tenantID,
			ProviderUserID: "google-user-1",
			Email:          "alice@example.com",
			DisplayName:    "Alice Johnson",
			Role:           "CEO",
			CreatedAt:      time.Now(),
		},
	}

	return users, nil
}

// GetEmails fetches emails for a specific user from Gmail API
// In production, we'd batch message.get requests and use goroutines for concurrency.
func (c *GoogleClient) GetEmails(ctx context.Context, userID uuid.UUID, receivedAfter time.Time) ([]domain.Email, error) {
	// Mock implementation - returns sample email with typosquatting + reply-to mismatch

	email := domain.Email{
		ID:                uuid.New(),
		TenantID:          uuid.UUID{}, // Will be set by application layer
		UserID:            userID,
		ProviderMessageID: "gmail-msg-001",
		Subject:           "Invoice #4821 - Payment Required",
		SenderEmail:       extractEmail("Accounts Payable <accounts@companny.com>"), // Typosquatting: "companny" vs "company"
		SenderName:        "accounts@companny.com",
		RecipientEmail:    "alice@example.com",
		ReceivedAt:        time.Now().Add(-2 * time.Hour),
		HasAttachments:    false,
		BodyPreview:       "Please find attached invoice for immediate payment. Wire transfer to the new account urgently.",
		Headers: map[string]string{
			"Reply-To": "urgent-payments@gmail.com", // Reply-to mismatch indicator
		},
		IngestedAt: time.Now(),
	}

	return []domain.Email{email}, nil
}

// extractEmail parses email addresses using Go's standard library net/mail.ParseAddress
// Returns the email address part, or the original string if parsing fails (graceful degradation)
func extractEmail(s string) string {
	addr, err := mail.ParseAddress(s)
	if err != nil {
		log.Printf("Warning: failed to parse email address %q: %v", s, err)
		return s
	}
	return addr.Address
}
