package domain

import (
	"time"

	"github.com/google/uuid"
)

// Provider represents email service providers we support
type Provider string

const (
	ProviderMicrosoft Provider = "microsoft"
	ProviderGoogle    Provider = "google"
)

// Tenant represents an organization using our email security service
type Tenant struct {
	ID          uuid.UUID `json:"id"`
	Name        string    `json:"name"`
	Provider    Provider  `json:"provider"`
	Credentials string    `json:"-"` // OAuth tokens, never expose in JSON
	Status      string    `json:"status"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// User represents an email user within a tenant's organization
type User struct {
	ID             uuid.UUID `json:"id"`
	TenantID       uuid.UUID `json:"tenant_id"`
	ProviderUserID string    `json:"provider_user_id"`
	Email          string    `json:"email"`
	DisplayName    string    `json:"display_name"`
	Role           string    `json:"role,omitempty"`
	CreatedAt      time.Time `json:"created_at"`
}

// Email represents an email message retrieved from provider APIs
//
// Simplification: we store a single recipient_email instead of a JSONB array.
// In production, emails have multiple recipients (to/cc/bcc). This would be
// modeled either as a dedicated recipients table (normalized) or a JSONB array.
// For this prototype, a single recipient is sufficient to demonstrate the
// ingestion and detection pipeline.
type Email struct {
	ID                uuid.UUID         `json:"id"`
	TenantID          uuid.UUID         `json:"tenant_id"`
	UserID            uuid.UUID         `json:"user_id"`
	ProviderMessageID string            `json:"provider_message_id"`
	Subject           string            `json:"subject"`
	SenderEmail       string            `json:"sender_email"`
	SenderName        string            `json:"sender_name"`
	RecipientEmail    string            `json:"recipient_email"`
	ReceivedAt        time.Time         `json:"received_at"`
	HasAttachments    bool              `json:"has_attachments"`
	AttachmentNames   []string          `json:"attachment_names,omitempty"`
	BodyPreview       string            `json:"body_preview"` // First 500 chars
	Headers           map[string]string `json:"headers"`
	IngestedAt        time.Time         `json:"ingested_at"`
	ProcessedAt       *time.Time        `json:"processed_at,omitempty"`
}

// FraudAnalysis represents the result of fraud detection on an email
//
// Simplification: we omit review workflow fields (reviewed_by, review_status,
// review_notes). In production, a human review loop is critical — security
// teams need to confirm or dismiss detections, and that feedback feeds back
// into model tuning.
type FraudAnalysis struct {
	ID              uuid.UUID   `json:"id"`
	EmailID         uuid.UUID   `json:"email_id"`
	RiskScore       float64     `json:"risk_score"` // 0.0 to 1.0
	RiskLevel       string      `json:"risk_level"` // "low", "medium", "high", "critical"
	DetectedThreats []Detection `json:"detected_threats"`
	AnalyzedAt      time.Time   `json:"analyzed_at"`
}

// Detection represents a single fraud detection signal
type Detection struct {
	Type       string  `json:"type"`       // e.g., "DOMAIN_TYPOSQUATTING"
	Confidence float64 `json:"confidence"` // 0.0 to 1.0
	Evidence   string  `json:"evidence"`   // Human-readable explanation
}

// RiskLevel converts a risk score to a categorical level
func RiskLevel(score float64) string {
	switch {
	case score >= 0.85:
		return "critical"
	case score >= 0.70:
		return "high"
	case score >= 0.50:
		return "medium"
	case score >= 0.30:
		return "low"
	default:
		return "none"
	}
}
