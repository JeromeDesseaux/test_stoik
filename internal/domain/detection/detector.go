package detection

import (
	"math"

	"github.com/stoik/email-security/internal/domain"
)

// Detector performs fraud detection on emails using pluggable strategies
//
// The Detector coordinates multiple DetectionStrategy implementations, each
// responsible for detecting a specific type of fraud (typosquatting, BEC, etc.).
//
// This design follows the Strategy pattern, providing:
//   - Modularity: Each detection type is independently developed and tested
//   - Extensibility: New strategies can be added without modifying existing code
//   - Testability: Strategies can be tested in isolation
//   - Configurability: Strategies can be enabled/disabled per organization
//
// In production, this would support:
//   - Dynamic strategy loading based on organization policies
//   - Per-strategy confidence thresholds and weights
//   - A/B testing of detection strategies
//   - Machine learning strategies alongside rule-based ones
type Detector struct {
	strategies []DetectionStrategy
	context    *DetectionContext
}

// NewDetector creates a new fraud detector with all standard detection strategies
//
// The detector is initialized with a fixed set of strategies. In production,
// this could be made configurable to enable/disable strategies per tenant.
func NewDetector(internalDomains, trustedDomains []string) *Detector {
	context := NewDetectionContext(internalDomains, trustedDomains)

	// Initialize all detection strategies
	// Each strategy implements the DetectionStrategy interface
	strategies := []DetectionStrategy{
		NewDisplayNameStrategy(),
		NewTyposquattingStrategy(),
		NewAuthFailuresStrategy(),
		NewUrgencyFinancialStrategy(),
		NewReplyToStrategy(),
		NewAttachmentStrategy(),
		NewBECRoleStrategy(),
	}

	return &Detector{
		strategies: strategies,
		context:    context,
	}
}

// AnalyzeEmail runs all detection strategies on an email and returns fraud analysis
func (d *Detector) AnalyzeEmail(email domain.Email, recipient *domain.User) domain.FraudAnalysis {
	detections := make([]domain.Detection, 0)

	// Run all detection strategies
	// Each strategy returns nil if no threat detected, or a Detection if suspicious
	for _, strategy := range d.strategies {
		if det := strategy.Detect(email, recipient, d.context); det != nil {
			detections = append(detections, *det)
		}
	}

	// Calculate aggregate risk score
	riskScore := d.calculateRiskScore(detections)

	return domain.FraudAnalysis{
		EmailID:         email.ID,
		RiskScore:       riskScore,
		RiskLevel:       domain.RiskLevel(riskScore),
		DetectedThreats: detections,
	}
}

// calculateRiskScore aggregates multiple detection signals into single score
func (d *Detector) calculateRiskScore(detections []domain.Detection) float64 {
	if len(detections) == 0 {
		return 0.0
	}

	// Weight by detection type (some types are more reliable than others)
	// Production : This should be a dedicated table to be editable quickly for finetunning
	weights := map[string]float64{
		"DOMAIN_TYPOSQUATTING":                1.5,
		"DISPLAY_NAME_MISMATCH":               1.3,
		"AUTH_FAILURES":                       1.2,
		"HIGH_RISK_ATTACHMENT":                1.5,
		"SUSPICIOUS_ATTACHMENT_NAME":          1.3,
		"URGENCY_FINANCIAL_LANGUAGE":          1.0,
		"REPLY_TO_MISMATCH":                   1.1,
		"MEDIUM_RISK_ATTACHMENT_WITH_URGENCY": 1.0,
		"BEC_CSUITE_TARGETING":                1.6,
		"BEC_FINANCE_TARGETING":               1.5,
		"BEC_HR_W2_SCAM":                      1.4,
		"BEC_HIGH_VALUE_TARGET":               1.2,
	}

	maxScore := 0.0
	for _, detection := range detections {
		weight := weights[detection.Type]
		if weight == 0 {
			weight = 1.0 // Default weight for unknown types
		}

		score := detection.Confidence * weight
		if score > maxScore {
			maxScore = score
		}
	}

	// Cap at 1.0 to ensure RiskLevel categories work correctly
	return math.Min(maxScore, 1.0)
}
