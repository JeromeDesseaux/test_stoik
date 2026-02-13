package ports

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/stoik/email-security/internal/domain"
)

// EmailProvider defines the contract for fetching users and emails from external providers
type EmailProvider interface {
	// GetUsers fetches all users for a tenant from the provider
	GetUsers(ctx context.Context, tenantID uuid.UUID) ([]domain.User, error)

	// GetEmails fetches emails for a specific user within a date range
	// receivedAfter is used to implement incremental sync (only fetch new emails since last run)
	GetEmails(ctx context.Context, userID uuid.UUID, receivedAfter time.Time) ([]domain.Email, error)
}
