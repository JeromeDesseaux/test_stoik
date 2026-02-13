package detection

import (
	"testing"

	"github.com/stoik/email-security/internal/domain"
	"github.com/stretchr/testify/assert"
)

func TestTyposquattingStrategy_Detect(t *testing.T) {
	context := NewDetectionContext(
		[]string{"company.com"},
		[]string{"microsoft.com", "paypal.com"},
	)

	tests := []struct {
		name            string
		senderEmail     string
		expectDetection bool
	}{
		{
			name:            "Exact match - no detection",
			senderEmail:     "user@microsoft.com",
			expectDetection: false,
		},
		{
			name:            "Typosquatting - micros0ft.com",
			senderEmail:     "user@micros0ft.com",
			expectDetection: true,
		},
		{
			name:            "Transposition microsfot.com - below threshold (84.6% < 85%)",
			senderEmail:     "user@microsfot.com",
			expectDetection: false, // 2 edits on 13-char domain = 84.6% similarity
		},
		{
			name:            "Typosquatting - paypa1.com",
			senderEmail:     "user@paypa1.com",
			expectDetection: true,
		},
		{
			name:            "Completely different domain",
			senderEmail:     "user@example.com",
			expectDetection: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			email := domain.Email{SenderEmail: tt.senderEmail}
			detection := NewTyposquattingStrategy().Detect(email, nil, context)

			if tt.expectDetection {
				assert.NotNil(t, detection, "Expected typosquatting detection")
				assert.Equal(t, "DOMAIN_TYPOSQUATTING", detection.Type)
				assert.Greater(t, detection.Confidence, 0.8)
			} else {
				assert.Nil(t, detection, "Expected no detection")
			}
		})
	}
}
