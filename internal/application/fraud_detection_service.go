package application

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/google/uuid"
	"github.com/stoik/email-security/internal/domain"
	"github.com/stoik/email-security/internal/domain/detection"
	"github.com/stoik/email-security/internal/ports"
)

// FraudDetectionService orchestrates email ingestion and fraud detection
type FraudDetectionService struct {
	storage  ports.Storage
	detector *detection.Detector

	// Provider registry maps domain.Provider to EmailProvider implementation
	// This allows supporting multiple providers (Microsoft, Google) dynamically
	// based on tenant configuration
	providers map[domain.Provider]ports.EmailProvider
}

// NewFraudDetectionService creates a new fraud detection service with dependency injection
func NewFraudDetectionService(
	storage ports.Storage,
	detector *detection.Detector,
	providers map[domain.Provider]ports.EmailProvider,
) *FraudDetectionService {
	return &FraudDetectionService{
		storage:   storage,
		detector:  detector,
		providers: providers,
	}
}

// IngestEmailsForTenant fetches emails from provider and stores them
// Error handling strategy:
//   - Individual user/email failures are logged but don't halt the pipeline
//   - This ensures partial success: if 1 of 100 users fails, we still ingest 99
//   - Critical failures return error to caller
func (s *FraudDetectionService) IngestEmailsForTenant(ctx context.Context, tenant *domain.Tenant) error {
	log.Printf("Ingesting emails for tenant: %s (%s)", tenant.Name, tenant.Provider)

	provider, ok := s.providers[tenant.Provider]
	if !ok {
		return fmt.Errorf("unsupported provider: %s", tenant.Provider)
	}

	// Fetch users from provider API
	users, err := provider.GetUsers(ctx, tenant.ID)
	if err != nil {
		return fmt.Errorf("failed to fetch users: %w", err)
	}

	// Store users (upsert pattern: update if exists, insert if new)
	// This handles scenarios where user metadata changes (role updates, name changes)
	for i := range users {
		users[i].TenantID = tenant.ID // Ensure tenant linkage
		if err := s.storage.CreateUser(ctx, &users[i]); err != nil {
			log.Printf("Failed to create user %s: %v", users[i].Email, err)
			continue // Don't fail entire ingestion if one user fails
		}
		log.Printf("Stored user: %s", users[i].Email)
	}

	// Fetch emails for each user
	// In production, this would be persisted per-user (e.g., users.last_sync_at)
	receivedAfter := time.Now().Add(-7 * 24 * time.Hour) // Last 7 days
	emailCount := 0

	for _, user := range users {
		emails, err := provider.GetEmails(ctx, user.ID, receivedAfter)
		if err != nil {
			log.Printf("Failed to fetch emails for user %s: %v", user.Email, err)
			continue // Don't fail entire ingestion if one user's emails fail
		}

		for i := range emails {
			emails[i].TenantID = tenant.ID
			emails[i].UserID = user.ID
			if err := s.storage.CreateEmail(ctx, &emails[i]); err != nil {
				log.Printf("Failed to store email %s: %v", emails[i].ProviderMessageID, err)
				continue
			}
			emailCount++
		}
	}

	log.Printf("Ingested %d emails", emailCount)
	return nil
}

// ProcessUnprocessedEmails runs fraud detection on all unprocessed emails
// Processing guarantees:
//   - Emails are processed at-least-once (if analysis fails, email stays unprocessed)
//   - Individual failures don't block batch (logged and skipped)
//   - High-risk emails trigger console alerts for demo purposes
func (s *FraudDetectionService) ProcessUnprocessedEmails(ctx context.Context, tenantID uuid.UUID) error {
	log.Println("Processing unprocessed emails...")

	emails, err := s.storage.GetUnprocessedEmails(ctx, 100)
	if err != nil {
		return fmt.Errorf("failed to fetch unprocessed emails: %w", err)
	}

	log.Printf("Found %d unprocessed emails", len(emails))

	for _, email := range emails {
		// Get recipient user for BEC role-based detection
		// If recipient not found (external email, user deleted), detection continues
		// without role-based signals
		recipient, err := s.storage.GetUserByEmail(ctx, email.TenantID, email.RecipientEmail)
		if err != nil {
			log.Printf("Failed to fetch recipient user for email %s: %v", email.ID, err)
		}

		// Run fraud detection (pure domain logic, no I/O
		analysis := s.detector.AnalyzeEmail(email, recipient)

		// Store analysis result
		if err := s.storage.CreateFraudAnalysis(ctx, &analysis); err != nil {
			log.Printf("Failed to store fraud analysis for email %s: %v", email.ID, err)
			continue // Don't mark as processed if analysis storage fails
		}

		// Mark email as processed (only after successful analysis storage)
		if err := s.storage.MarkEmailProcessed(ctx, email.ID); err != nil {
			log.Printf("Failed to mark email as processed %s: %v", email.ID, err)
		}

		// Log high-risk detections (for demo purposes)
		// In production, this would:
		//   - Send webhook to security
		//   - Send Slack alert to security team
		// 	 - Send email/sms or whatever alerting system to the user
		//   - Quarantine email via provider API
		if analysis.RiskLevel == "high" || analysis.RiskLevel == "critical" {
			log.Printf("🚨 HIGH RISK EMAIL DETECTED:")
			log.Printf("  Subject: %s", email.Subject)
			log.Printf("  From: %s <%s>", email.SenderName, email.SenderEmail)
			log.Printf("  Risk Score: %.2f (%s)", analysis.RiskScore, analysis.RiskLevel)
			log.Printf("  Threats Detected: %d", len(analysis.DetectedThreats))
			for _, threat := range analysis.DetectedThreats {
				log.Printf("    - %s (%.0f%% confidence): %s",
					threat.Type, threat.Confidence*100, threat.Evidence)
			}
			log.Println()
		}
	}

	return nil
}

// GetHighRiskSummary retrieves high-risk emails for a tenant
func (s *FraudDetectionService) GetHighRiskSummary(ctx context.Context, tenantID uuid.UUID, limit int) ([]domain.FraudAnalysis, error) {
	return s.storage.GetHighRiskEmails(ctx, tenantID, limit)
}
