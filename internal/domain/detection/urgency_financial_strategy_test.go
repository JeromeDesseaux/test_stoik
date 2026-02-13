package detection

import (
	"testing"

	"github.com/stoik/email-security/internal/domain"
	"github.com/stretchr/testify/assert"
)

func TestUrgencyFinancialStrategy_Detect(t *testing.T) {
	context := NewDetectionContext([]string{}, []string{})

	tests := []struct {
		name            string
		subject         string
		body            string
		expectDetection bool
	}{
		{
			name:            "Urgent wire transfer - should detect",
			subject:         "URGENT: Wire Transfer Needed",
			body:            "Please process this wire transfer immediately to our bank account",
			expectDetection: true,
		},
		{
			name:            "Normal invoice - no urgency",
			subject:         "Invoice #12345",
			body:            "Please find attached invoice for services rendered.",
			expectDetection: false,
		},
		{
			name:            "CEO requesting gift cards - classic scam",
			subject:         "Need this done today",
			body:            "Hi, I need you to purchase some iTunes gift cards urgently. Please send codes ASAP. CEO",
			expectDetection: true,
		},
		{
			name:            "Urgent but no financial keywords",
			subject:         "Urgent: Meeting today",
			body:            "We need to meet today to discuss the project.",
			expectDetection: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			email := domain.Email{
				Subject:     tt.subject,
				BodyPreview: tt.body,
			}
			detection := NewUrgencyFinancialStrategy().Detect(email, nil, context)

			if tt.expectDetection {
				assert.NotNil(t, detection, "Expected urgency/financial detection")
				assert.Equal(t, "URGENCY_FINANCIAL_LANGUAGE", detection.Type)
				assert.Greater(t, detection.Confidence, 0.6)
			} else {
				assert.Nil(t, detection, "Expected no detection")
			}
		})
	}
}
