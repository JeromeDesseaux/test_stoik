package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	_ "github.com/lib/pq"
	"github.com/stoik/email-security/internal/domain"
)

// PostgresStore implements ports.Storage for PostgreSQL
type PostgresStore struct {
	db *sql.DB
}

// NewPostgresStore creates a new PostgreSQL storage instance
func NewPostgresStore(connStr string) (*PostgresStore, error) {
	db, err := sql.Open("postgres", connStr)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	// Test connection
	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	// Set connection pool settings
	// In production, should be set based on workload
	db.SetMaxOpenConns(5)
	db.SetMaxIdleConns(1)
	db.SetConnMaxLifetime(5 * time.Minute)

	return &PostgresStore{db: db}, nil
}

// Close closes the database connection
func (s *PostgresStore) Close() error {
	return s.db.Close()
}

// InitSchema creates database tables if they don't exist
// In production, use proper migration tools
func (s *PostgresStore) InitSchema() error {
	schema := `
	-- ============================================================================
	-- TENANTS TABLE
	-- ============================================================================
	-- Multi-tenant architecture: each tenant = one organization using our service.
	-- Credentials stored as encrypted OAuth tokens (TEXT is sufficient for prototype).
	--
	-- Production: use a secrets manager (AWS Secrets Manager, Vault) instead of DB storage.
	CREATE TABLE IF NOT EXISTS tenants (
		id UUID PRIMARY KEY,
		name VARCHAR(100) NOT NULL,
		provider VARCHAR(10) NOT NULL CHECK (provider IN ('microsoft', 'google')),
		credentials TEXT NOT NULL,
		status VARCHAR(20) DEFAULT 'active',
		created_at TIMESTAMP DEFAULT NOW(),
		updated_at TIMESTAMP DEFAULT NOW()
	);

	-- ============================================================================
	-- USERS TABLE
	-- ============================================================================
	-- Represents email users within a tenant's organization (synced from provider APIs).
	--
	-- Production considerations:
	-- - Add role/title for executive impersonation detection
	-- - Add manager_id for org chart modeling (detect requests bypassing approval chains)
	-- - Add last_active_at for dormant account detection
	-- - Extract those into a dedicated table for proper BEC (Business Email COmpromise) detection
	--
	-- Here we'll simplify to a single "role" column.

	CREATE TABLE IF NOT EXISTS users (
		id UUID PRIMARY KEY,
		tenant_id UUID REFERENCES tenants(id) ON DELETE CASCADE,
		provider_user_id VARCHAR(64) NOT NULL,
		email VARCHAR(254) NOT NULL,
		display_name VARCHAR(100),
		role VARCHAR(50),
		created_at TIMESTAMP DEFAULT NOW(),
		UNIQUE(tenant_id, provider_user_id)
	);

	-- Backs GetUserByEmail
	CREATE INDEX IF NOT EXISTS idx_users_tenant_email ON users(tenant_id, email);

	-- ============================================================================
	-- EMAILS TABLE
	-- ============================================================================
	-- Core table storing email metadata for fraud analysis.
	--
	-- Prototype simplifications:
	-- 1. Single recipient_email instead of multiple recipients (to/cc/bcc)
	--    Why: Sufficient to demonstrate the detection pipeline for this assessment
	--    Production: Dedicated email_recipients table with columns [{email_id, email, type("cc", "bcc", "to"...)}]
	--
	-- 2. attachment_names as JSONB string array
	--    Why: An email can have multiple attachments (e.g. ["invoice.pdf", "wire.xlsx"]). I don't really like JSONB
	--    as it violates First Normal Form, but it simplifies the work for this test and is acceptable here IMHO.
	--
	--    Production: Dedicated attachments table with (id, email_id, filename, size, mime_type, hash)
	--                Enables deep analysis (malware scanning, hash-based deduplication)
	--
	-- 3. body_preview (500 chars) instead of full body
	--    Why: Full email bodies can be MB-sized (HTML, inline images, base64 attachments)
	--         Storing them in the main table bloats rows and kills querying performance
	--    Production: Store full bodies in S3 or a separate email_bodies table; keep only
	--                a preview in the hot table for display and keyword-based detection
	--
	-- 4. headers as JSONB key-value map -- same logic than attachments
	--    Why: Flexible storage for authentication headers (SPF, DKIM, DMARC) and routing info
	--    Production: Dedicated headers table for efficient querying (e.g., "all emails with DMARC=fail")
	--
	-- Scaling considerations for production (not implemented in prototype):
	-- - PARTITION BY RANGE(ingested_at): enables efficient time-based queries and cheap partition drops
	-- - Retention policy: DROP old partitions monthly (e.g., "DROP TABLE emails_2025_01") instead of
	--   expensive DELETE operations that cause table bloat and long-running transactions
	-- - Auto-partition creation: use cron job to create future partitions

	CREATE TABLE IF NOT EXISTS emails (
		id UUID PRIMARY KEY,
		tenant_id UUID REFERENCES tenants(id) ON DELETE CASCADE,
		user_id UUID REFERENCES users(id) ON DELETE CASCADE,
		provider_message_id VARCHAR(255) NOT NULL,
		subject TEXT,
		sender_email VARCHAR(254) NOT NULL,
		sender_name VARCHAR(100),
		recipient_email VARCHAR(254) NOT NULL,
		received_at TIMESTAMP NOT NULL,
		has_attachments BOOLEAN DEFAULT FALSE,
		attachment_names JSONB,
		body_preview TEXT,
		headers JSONB,
		ingested_at TIMESTAMP NOT NULL DEFAULT NOW(),
		processed_at TIMESTAMP,
		UNIQUE(tenant_id, provider_message_id)
	);

	-- Latest emails per tenant "most recent first"
	CREATE INDEX IF NOT EXISTS idx_emails_received_at ON emails(tenant_id, received_at DESC);
	-- Fraud investigation: "show all emails from this suspicious sender within a tenant"
	CREATE INDEX IF NOT EXISTS idx_emails_sender ON emails(tenant_id, sender_email);
	-- Per-user inbox view ordered by time, for investigating a specific mailbox
	CREATE INDEX IF NOT EXISTS idx_emails_user ON emails(user_id, received_at DESC);

	-- ============================================================================
	-- FRAUD_ANALYSES TABLE
	-- ============================================================================
	-- Stores the output of fraud detection: risk score, risk level, and detected threats.
	--
	-- Prototype simplifications:
	-- 1. detected_threats as JSONB array of {type, confidence, evidence}
	--    Why: Detections are always read alongside their parent analysis (no need for joins)
	--    Production: Dedicated detections table (id, analysis_id, type, confidence, evidence)
	--                Enables queries like "all typosquatting detections this week" and indexing by type
	--                Allows per-detection metadata (e.g., detection_model_version, detection_timestamp)
	--
	-- 2. No review workflow columns (review_status, review_notes, reviewed_by, reviewed_at)
	--    Why: Sufficient for prototype demonstration
	--    Production: A human review loop is ESSENTIAL for tuning detection precision
	--                Security teams must confirm or dismiss detections; feedback feeds back into model tuning and ML models.
	--
	-- 3. No versioning or A/B testing columns (model_version, experiment_id)
	--    Production: Track which detection model version produced each analysis for debugging and rollback

	CREATE TABLE IF NOT EXISTS fraud_analyses (
		id UUID PRIMARY KEY,
		email_id UUID REFERENCES emails(id) ON DELETE CASCADE,
		risk_score DECIMAL(5,4) NOT NULL,
		risk_level VARCHAR(10) NOT NULL,
		detected_threats JSONB,
		analyzed_at TIMESTAMP DEFAULT NOW()
	);

	-- Backs GetHighRiskEmails: filters on risk_level, orders by analyzed_at DESC for dashboard
	CREATE INDEX IF NOT EXISTS idx_fraud_risk ON fraud_analyses(risk_level, analyzed_at DESC);
	-- FK lookup: makes the JOIN emails ON fa.email_id = e.id efficient (avoids seq scan)
	CREATE INDEX IF NOT EXISTS idx_fraud_email ON fraud_analyses(email_id);
	`

	_, err := s.db.Exec(schema)
	return err
}

// CreateTenant inserts a new tenant
func (s *PostgresStore) CreateTenant(ctx context.Context, tenant *domain.Tenant) error {
	query := `
		INSERT INTO tenants (id, name, provider, credentials, status, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
	`
	_, err := s.db.ExecContext(ctx, query,
		tenant.ID, tenant.Name, tenant.Provider, tenant.Credentials,
		tenant.Status, tenant.CreatedAt, tenant.UpdatedAt,
	)
	return err
}

// GetTenant retrieves a tenant by ID
func (s *PostgresStore) GetTenant(ctx context.Context, id uuid.UUID) (*domain.Tenant, error) {
	query := `
		SELECT id, name, provider, credentials, status, created_at, updated_at
		FROM tenants
		WHERE id = $1
	`
	tenant := &domain.Tenant{}
	err := s.db.QueryRowContext(ctx, query, id).Scan(
		&tenant.ID, &tenant.Name, &tenant.Provider, &tenant.Credentials,
		&tenant.Status, &tenant.CreatedAt, &tenant.UpdatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return tenant, err
}

// CreateUser inserts a new user
func (s *PostgresStore) CreateUser(ctx context.Context, user *domain.User) error {
	query := `
		INSERT INTO users (id, tenant_id, provider_user_id, email, display_name, role, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		ON CONFLICT (tenant_id, provider_user_id) DO UPDATE
		SET email = EXCLUDED.email,
		    display_name = EXCLUDED.display_name,
		    role = EXCLUDED.role
	`
	_, err := s.db.ExecContext(ctx, query,
		user.ID, user.TenantID, user.ProviderUserID, user.Email,
		user.DisplayName, user.Role, user.CreatedAt,
	)
	return err
}

// GetUserByEmail retrieves a user by email and tenant
func (s *PostgresStore) GetUserByEmail(ctx context.Context, tenantID uuid.UUID, email string) (*domain.User, error) {
	query := `
		SELECT id, tenant_id, provider_user_id, email, display_name, role, created_at
		FROM users
		WHERE tenant_id = $1 AND email = $2
	`
	user := &domain.User{}
	err := s.db.QueryRowContext(ctx, query, tenantID, email).Scan(
		&user.ID, &user.TenantID, &user.ProviderUserID, &user.Email,
		&user.DisplayName, &user.Role, &user.CreatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return user, err
}

// CreateEmail inserts a new email
func (s *PostgresStore) CreateEmail(ctx context.Context, email *domain.Email) error {
	attachmentJSON, err := json.Marshal(email.AttachmentNames)
	if err != nil {
		return fmt.Errorf("failed to marshal attachment names: %w", err)
	}

	headersJSON, err := json.Marshal(email.Headers)
	if err != nil {
		return fmt.Errorf("failed to marshal headers: %w", err)
	}

	query := `
		INSERT INTO emails (
			id, tenant_id, user_id, provider_message_id, subject,
			sender_email, sender_name, recipient_email, received_at,
			has_attachments, attachment_names, body_preview, headers,
			ingested_at, processed_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
		ON CONFLICT (tenant_id, provider_message_id) DO NOTHING
	`
	_, err = s.db.ExecContext(ctx, query,
		email.ID, email.TenantID, email.UserID, email.ProviderMessageID,
		email.Subject, email.SenderEmail, email.SenderName, email.RecipientEmail,
		email.ReceivedAt, email.HasAttachments, attachmentJSON, email.BodyPreview,
		headersJSON, email.IngestedAt, email.ProcessedAt,
	)
	return err
}

// GetEmail retrieves an email by ID
func (s *PostgresStore) GetEmail(ctx context.Context, id uuid.UUID) (*domain.Email, error) {
	query := `
		SELECT id, tenant_id, user_id, provider_message_id, subject,
		       sender_email, sender_name, recipient_email, received_at,
		       has_attachments, attachment_names, body_preview, headers,
		       ingested_at, processed_at
		FROM emails
		WHERE id = $1
	`
	email := &domain.Email{}
	var attachmentJSON, headersJSON []byte

	err := s.db.QueryRowContext(ctx, query, id).Scan(
		&email.ID, &email.TenantID, &email.UserID, &email.ProviderMessageID,
		&email.Subject, &email.SenderEmail, &email.SenderName, &email.RecipientEmail,
		&email.ReceivedAt, &email.HasAttachments, &attachmentJSON, &email.BodyPreview,
		&headersJSON, &email.IngestedAt, &email.ProcessedAt,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	json.Unmarshal(attachmentJSON, &email.AttachmentNames)
	json.Unmarshal(headersJSON, &email.Headers)

	return email, nil
}

// GetUnprocessedEmails retrieves emails that haven't been analyzed yet
func (s *PostgresStore) GetUnprocessedEmails(ctx context.Context, limit int) ([]domain.Email, error) {
	query := `
		SELECT id, tenant_id, user_id, provider_message_id, subject,
		       sender_email, sender_name, recipient_email, received_at,
		       has_attachments, attachment_names, body_preview, headers,
		       ingested_at, processed_at
		FROM emails
		WHERE processed_at IS NULL
		ORDER BY received_at ASC
		LIMIT $1
	`
	rows, err := s.db.QueryContext(ctx, query, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	emails := make([]domain.Email, 0)
	for rows.Next() {
		var email domain.Email
		var attachmentJSON, headersJSON []byte

		err := rows.Scan(
			&email.ID, &email.TenantID, &email.UserID, &email.ProviderMessageID,
			&email.Subject, &email.SenderEmail, &email.SenderName, &email.RecipientEmail,
			&email.ReceivedAt, &email.HasAttachments, &attachmentJSON, &email.BodyPreview,
			&headersJSON, &email.IngestedAt, &email.ProcessedAt,
		)
		if err != nil {
			return nil, err
		}

		json.Unmarshal(attachmentJSON, &email.AttachmentNames)
		json.Unmarshal(headersJSON, &email.Headers)

		emails = append(emails, email)
	}

	return emails, rows.Err()
}

// MarkEmailProcessed updates email's processed_at timestamp
func (s *PostgresStore) MarkEmailProcessed(ctx context.Context, emailID uuid.UUID) error {
	query := `UPDATE emails SET processed_at = NOW() WHERE id = $1`
	_, err := s.db.ExecContext(ctx, query, emailID)
	return err
}

// CreateFraudAnalysis inserts a fraud analysis result
func (s *PostgresStore) CreateFraudAnalysis(ctx context.Context, analysis *domain.FraudAnalysis) error {
	threatsJSON, err := json.Marshal(analysis.DetectedThreats)
	if err != nil {
		return fmt.Errorf("failed to marshal threats: %w", err)
	}

	query := `
		INSERT INTO fraud_analyses (id, email_id, risk_score, risk_level, detected_threats, analyzed_at)
		VALUES ($1, $2, $3, $4, $5, $6)
	`
	_, err = s.db.ExecContext(ctx, query,
		uuid.New(), analysis.EmailID, analysis.RiskScore, analysis.RiskLevel,
		threatsJSON, time.Now(),
	)
	return err
}

// GetHighRiskEmails retrieves emails with high/critical risk levels
func (s *PostgresStore) GetHighRiskEmails(ctx context.Context, tenantID uuid.UUID, limit int) ([]domain.FraudAnalysis, error) {
	query := `
		SELECT fa.id, fa.email_id, fa.risk_score, fa.risk_level,
		       fa.detected_threats, fa.analyzed_at
		FROM fraud_analyses fa
		JOIN emails e ON fa.email_id = e.id
		WHERE e.tenant_id = $1 AND fa.risk_level IN ('high', 'critical')
		ORDER BY fa.risk_score DESC, fa.analyzed_at DESC
		LIMIT $2
	`
	rows, err := s.db.QueryContext(ctx, query, tenantID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	analyses := make([]domain.FraudAnalysis, 0)
	for rows.Next() {
		var analysis domain.FraudAnalysis
		var threatsJSON []byte

		err := rows.Scan(
			&analysis.ID, &analysis.EmailID, &analysis.RiskScore, &analysis.RiskLevel,
			&threatsJSON, &analysis.AnalyzedAt,
		)
		if err != nil {
			return nil, err
		}

		json.Unmarshal(threatsJSON, &analysis.DetectedThreats)
		analyses = append(analyses, analysis)
	}

	return analyses, rows.Err()
}
