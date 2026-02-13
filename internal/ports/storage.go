package ports

import (
	"context"

	"github.com/google/uuid"
	"github.com/stoik/email-security/internal/domain"
)

// Storage defines the contract for persisting and querying domain entities
type Storage interface {
	// Tenant operations
	CreateTenant(ctx context.Context, tenant *domain.Tenant) error
	GetTenant(ctx context.Context, id uuid.UUID) (*domain.Tenant, error)

	// User operations
	CreateUser(ctx context.Context, user *domain.User) error
	GetUserByEmail(ctx context.Context, tenantID uuid.UUID, email string) (*domain.User, error)

	// Email operations
	CreateEmail(ctx context.Context, email *domain.Email) error
	GetEmail(ctx context.Context, id uuid.UUID) (*domain.Email, error)
	GetUnprocessedEmails(ctx context.Context, limit int) ([]domain.Email, error)
	MarkEmailProcessed(ctx context.Context, emailID uuid.UUID) error

	// Fraud analysis operations
	CreateFraudAnalysis(ctx context.Context, analysis *domain.FraudAnalysis) error
	GetHighRiskEmails(ctx context.Context, tenantID uuid.UUID, limit int) ([]domain.FraudAnalysis, error)

	// Lifecycle
	Close() error
}
