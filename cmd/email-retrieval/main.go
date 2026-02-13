package main

import (
	"context"
	"log"
	"os"
	"time"

	"github.com/google/uuid"
	"github.com/stoik/email-security/internal/adapters/providers"
	"github.com/stoik/email-security/internal/adapters/storage"
	"github.com/stoik/email-security/internal/application"
	"github.com/stoik/email-security/internal/domain"
	"github.com/stoik/email-security/internal/domain/detection"
	"github.com/stoik/email-security/internal/ports"
)

func main() {
	log.Println("Starting Email Security Service...")

	// Configuration
	// In production, use proper config management (Viper, environment-specific configs)
	dbConnStr := getEnv("DATABASE_URL", "postgres://postgres:postgres@localhost:5432/email_security?sslmode=disable")
	internalDomains := []string{"company.com", "example.com"} // Would come from tenant config
	trustedDomains := []string{"microsoft.com", "google.com", "paypal.com"}

	// Initialize storage adapter (driven port implementation)
	store, err := storage.NewPostgresStore(dbConnStr)
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}
	defer store.Close()

	log.Println("Connected to PostgreSQL")

	// Initialize database schema
	if err := store.InitSchema(); err != nil {
		log.Fatalf("Failed to initialize schema: %v", err)
	}

	log.Println("Database schema initialized")

	// Initialize fraud detector (domain logic)
	detector := detection.NewDetector(internalDomains, trustedDomains)

	// Initialize provider adapters (driving port implementations)
	// This map enables dynamic provider selection based on tenant.Provider
	// without reflection or switch statements
	providerMap := map[domain.Provider]ports.EmailProvider{
		domain.ProviderMicrosoft: providers.NewMicrosoftClient(),
		domain.ProviderGoogle:    providers.NewGoogleClient(),
	}

	// Initialize application service (dependency injection via constructor)
	// This is the hexagonal architecture pattern: outer layers (main) wire up
	// dependencies and inject them into inner layers (application service)
	service := application.NewFraudDetectionService(store, detector, providerMap)

	// Create sample tenants for demonstration
	// In production, tenants would be managed via admin API
	ctx := context.Background()
	tenants := []*domain.Tenant{
		{
			ID:          uuid.New(),
			Name:        "Acme Insurance Co.",
			Provider:    domain.ProviderMicrosoft,
			Credentials: "encrypted_oauth_token_here", // In production: use Vault/Secrets Manager
			Status:      "active",
			CreatedAt:   time.Now(),
			UpdatedAt:   time.Now(),
		},
		{
			ID:          uuid.New(),
			Name:        "Beta Corp.",
			Provider:    domain.ProviderGoogle,
			Credentials: "encrypted_oauth_token_here",
			Status:      "active",
			CreatedAt:   time.Now(),
			UpdatedAt:   time.Now(),
		},
	}

	for _, tenant := range tenants {
		if err := store.CreateTenant(ctx, tenant); err != nil {
			log.Printf("Tenant creation skipped (may already exist): %v", err)
		} else {
			log.Printf("Created tenant: %s (%s)", tenant.Name, tenant.Provider)
		}
	}

	// Run the main processing loop
	// For this demo, we run a simple sequential pipeline to demonstrate the architecture

	log.Println("Starting email ingestion and detection loop...")

	// Phase 1: Ingestion
	for _, tenant := range tenants {
		if err := service.IngestEmailsForTenant(ctx, tenant); err != nil {
			log.Fatalf("Ingestion failed for tenant %s: %v", tenant.Name, err)
		}
	}

	// Phase 2: Detection
	for _, tenant := range tenants {
		if err := service.ProcessUnprocessedEmails(ctx, tenant.ID); err != nil {
			log.Fatalf("Processing failed for tenant %s: %v", tenant.Name, err)
		}
	}

	// Phase 3: Display summary
	for _, tenant := range tenants {
		highRiskEmails, err := service.GetHighRiskSummary(ctx, tenant.ID, 10)
		if err != nil {
			log.Fatalf("Failed to fetch high-risk emails: %v", err)
		}

		if len(highRiskEmails) > 0 {
			log.Printf("\n=== SECURITY ALERT: %d High-Risk Emails Detected for %s ===", len(highRiskEmails), tenant.Name)
			for i, analysis := range highRiskEmails {
				log.Printf("%d. Email ID: %s | Risk: %.2f (%s) | Threats: %d",
					i+1, analysis.EmailID, analysis.RiskScore, analysis.RiskLevel,
					len(analysis.DetectedThreats))
			}
			log.Println("===================================================")
		}
	}

	log.Println("Email security service completed successfully")
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}
