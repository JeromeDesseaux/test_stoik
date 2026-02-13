package detection

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stoik/email-security/internal/domain"
	"github.com/stretchr/testify/assert"
)

func TestDetector_CalculateRiskScore(t *testing.T) {
	detector := NewDetector([]string{}, []string{})

	tests := []struct {
		name          string
		detections    []domain.Detection
		expectedScore float64
		expectedLevel string
	}{
		{
			name:          "No detections - zero score",
			detections:    []domain.Detection{},
			expectedScore: 0.0,
			expectedLevel: "none",
		},
		{
			name: "Single high-confidence detection",
			detections: []domain.Detection{
				{Type: "DOMAIN_TYPOSQUATTING", Confidence: 0.90},
			},
			expectedScore: 1.0, // 0.90 * 1.5 weight = 1.35, capped at 1.0
			expectedLevel: "critical",
		},
		{
			name: "Multiple medium-confidence detections",
			detections: []domain.Detection{
				{Type: "URGENCY_FINANCIAL_LANGUAGE", Confidence: 0.70},
				{Type: "REPLY_TO_MISMATCH", Confidence: 0.75},
			},
			expectedScore: 0.825, // max(0.70*1.0, 0.75*1.1) = 0.825
			expectedLevel: "high",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			score := detector.calculateRiskScore(tt.detections)
			assert.InDelta(t, tt.expectedScore, score, 0.01, "Risk score mismatch")

			level := domain.RiskLevel(score)
			assert.Equal(t, tt.expectedLevel, level, "Risk level mismatch")
		})
	}
}

func TestDetector_AnalyzeEmail_Integration(t *testing.T) {
	detector := NewDetector(
		[]string{"company.com"},
		[]string{"microsoft.com"},
	)

	// Test case: CEO fraud email (multiple signals)
	email := domain.Email{
		ID:          uuid.New(),
		Subject:     "Urgent Wire Transfer Required",
		SenderName:  "John Smith, CEO",
		SenderEmail: "john@external-evil.com",
		BodyPreview: "I need you to process this wire transfer immediately. Send to bank account 12345. Do not discuss with anyone. Urgent!",
		Headers: map[string]string{
			"Reply-To":     "attacker@gmail.com",
			"Received-SPF": "fail",
		},
		ReceivedAt: time.Now(),
	}

	analysis := detector.AnalyzeEmail(email, nil)

	// Should detect multiple threats
	assert.Greater(t, len(analysis.DetectedThreats), 0, "Should detect threats")
	assert.Greater(t, analysis.RiskScore, 0.7, "Should have high risk score")
	assert.Contains(t, []string{"high", "critical"}, analysis.RiskLevel, "Should be high or critical risk")

	// Verify specific detections
	detectionTypes := make(map[string]bool)
	for _, detection := range analysis.DetectedThreats {
		detectionTypes[detection.Type] = true
	}

	assert.True(t, detectionTypes["DISPLAY_NAME_MISMATCH"], "Should detect display name mismatch")
	assert.True(t, detectionTypes["URGENCY_FINANCIAL_LANGUAGE"], "Should detect urgent financial language")
	assert.True(t, detectionTypes["REPLY_TO_MISMATCH"], "Should detect reply-to mismatch")
}
