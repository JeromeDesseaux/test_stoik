package providers

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/stoik/email-security/internal/domain"
)

// MicrosoftClient implements ports.EmailProvider for Microsoft Graph API
// For this prototype: returns mock data to demonstrate the pipeline
type MicrosoftClient struct{}

// NewMicrosoftClient creates a new Microsoft Graph API client
func NewMicrosoftClient() *MicrosoftClient {
	return &MicrosoftClient{}
}

// GetUsers fetches all users for a tenant from Microsoft Graph API
func (c *MicrosoftClient) GetUsers(ctx context.Context, tenantID uuid.UUID) ([]domain.User, error) {
	// Mock implementation - returns sample users

	users := []domain.User{
		{
			ID:             uuid.New(),
			TenantID:       tenantID,
			ProviderUserID: "user-1",
			Email:          "john.doe@company.com",
			DisplayName:    "John Doe",
			Role:           "CFO",
			CreatedAt:      time.Now(),
		},
		{
			ID:             uuid.New(),
			TenantID:       tenantID,
			ProviderUserID: "user-2",
			Email:          "jane.smith@company.com",
			DisplayName:    "Jane Smith",
			Role:           "HR Director",
			CreatedAt:      time.Now(),
		},
	}

	return users, nil
}

// GetEmails fetches emails for a specific user from Microsoft Graph API
func (c *MicrosoftClient) GetEmails(ctx context.Context, userID uuid.UUID, receivedAfter time.Time) ([]domain.Email, error) {
	// Mock implementation - returns sample email with BEC indicators

	email := domain.Email{
		ID:                uuid.New(),
		TenantID:          uuid.UUID{}, // Will be set by application layer
		UserID:            userID,
		ProviderMessageID: "msg-001",
		Subject:           "Urgent: Wire Transfer Needed",
		SenderEmail:       "john@external-domain.com",
		SenderName:        "CEO John Smith",
		RecipientEmail:    "john.doe@company.com",
		ReceivedAt:        time.Now().Add(-1 * time.Hour),
		HasAttachments:    false,
		BodyPreview:       "Please process this wire transfer immediately...",
		Headers:           make(map[string]string), // Would include SPF/DKIM/DMARC from internetMessageHeaders
		IngestedAt:        time.Now(),
	}

	return []domain.Email{email}, nil
}
