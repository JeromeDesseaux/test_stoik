package detection

import (
	"testing"

	"github.com/stoik/email-security/internal/domain"
	"github.com/stretchr/testify/assert"
)

func TestBECRoleStrategy_Detect(t *testing.T) {
	context := NewDetectionContext(
		[]string{"company.com"},
		[]string{},
	)

	tests := []struct {
		name            string
		email           domain.Email
		recipient       *domain.User
		expectDetection bool
		expectedType    string
		minConfidence   float64
	}{
		{
			name: "CEO receiving urgent wire transfer - HIGH risk",
			email: domain.Email{
				SenderEmail: "attacker@evil.com",
				Subject:     "URGENT: Wire Transfer Required",
				BodyPreview: "Please process this wire transfer immediately to our new bank account",
			},
			recipient: &domain.User{
				Role:  "CEO",
				Email: "ceo@company.com",
			},
			expectDetection: true,
			expectedType:    "BEC_CSUITE_TARGETING",
			minConfidence:   0.90,
		},
		{
			name: "CFO receiving urgent wire transfer - HIGH risk",
			email: domain.Email{
				SenderEmail: "fake@external.com",
				Subject:     "Urgent Payment Needed",
				BodyPreview: "Wire transfer must be completed asap",
			},
			recipient: &domain.User{
				Role:  "CFO",
				Email: "cfo@company.com",
			},
			expectDetection: true,
			expectedType:    "BEC_CSUITE_TARGETING",
			minConfidence:   0.90,
		},
		{
			name: "Finance Manager receiving payment request - HIGH risk",
			email: domain.Email{
				SenderEmail: "scammer@phish.com",
				Subject:     "Invoice Payment",
				BodyPreview: "Please process payment for invoice via wire transfer",
			},
			recipient: &domain.User{
				Role:  "Finance Manager",
				Email: "finance@company.com",
			},
			expectDetection: true,
			expectedType:    "BEC_FINANCE_TARGETING",
			minConfidence:   0.85,
		},
		{
			name: "HR Director receiving payroll request (France) - MEDIUM risk",
			email: domain.Email{
				SenderEmail: "external@gmail.com",
				Subject:     "Demande de bulletin de paie",
				BodyPreview: "Merci de m'envoyer le bulletin de salaire des employés",
			},
			recipient: &domain.User{
				Role:  "HR Director",
				Email: "hr@company.com",
			},
			expectDetection: true,
			expectedType:    "BEC_HR_PAYROLL_SCAM",
			minConfidence:   0.80,
		},
		{
			name: "Software Engineer receiving same content - NO detection",
			email: domain.Email{
				SenderEmail: "external@test.com",
				Subject:     "Urgent Payment Needed",
				BodyPreview: "Wire transfer must be completed immediately",
			},
			recipient: &domain.User{
				Role:  "Software Engineer",
				Email: "dev@company.com",
			},
			expectDetection: false,
		},
		{
			name: "Internal sender to CEO - NO detection",
			email: domain.Email{
				SenderEmail: "colleague@company.com",
				Subject:     "Urgent wire transfer needed",
				BodyPreview: "Please approve this payment",
			},
			recipient: &domain.User{
				Role:  "CEO",
				Email: "ceo@company.com",
			},
			expectDetection: false,
		},
		{
			name: "Nil recipient - NO detection",
			email: domain.Email{
				SenderEmail: "external@evil.com",
				Subject:     "Urgent wire transfer",
				BodyPreview: "Payment needed",
			},
			recipient:       nil,
			expectDetection: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			detection := NewBECRoleStrategy().Detect(tt.email, tt.recipient, context)

			if tt.expectDetection {
				assert.NotNil(t, detection, "Expected BEC detection but got nil")
				assert.Equal(t, tt.expectedType, detection.Type)
				assert.GreaterOrEqual(t, detection.Confidence, tt.minConfidence)
				assert.NotEmpty(t, detection.Evidence)
			} else {
				assert.Nil(t, detection, "Expected no BEC detection but got one")
			}
		})
	}
}
