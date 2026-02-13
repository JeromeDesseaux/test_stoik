package detection

import (
	"testing"

	"github.com/stoik/email-security/internal/domain"
	"github.com/stretchr/testify/assert"
)

func TestDisplayNameStrategy_Detect(t *testing.T) {
	strategy := NewDisplayNameStrategy()
	context := NewDetectionContext(
		[]string{"company.com"},
		[]string{"microsoft.com"},
	)

	tests := []struct {
		name            string
		email           domain.Email
		expectDetection bool
		expectedConf    float64
	}{
		{
			name: "CEO from external domain - should detect",
			email: domain.Email{
				SenderName:  "John Smith CEO",
				SenderEmail: "attacker@evil.com",
			},
			expectDetection: true,
			expectedConf:    0.85,
		},
		{
			name: "CEO from internal domain - should not detect",
			email: domain.Email{
				SenderName:  "John Smith CEO",
				SenderEmail: "john@company.com",
			},
			expectDetection: false,
		},
		{
			name: "Regular employee from external - should not detect",
			email: domain.Email{
				SenderName:  "Bob Jones",
				SenderEmail: "bob@external.com",
			},
			expectDetection: false,
		},
		{
			name: "CFO from external - should detect",
			email: domain.Email{
				SenderName:  "Jane Doe, CFO",
				SenderEmail: "jane@phishing.com",
			},
			expectDetection: true,
			expectedConf:    0.85,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			detection := strategy.Detect(tt.email, nil, context)

			if tt.expectDetection {
				assert.NotNil(t, detection, "Expected detection but got nil")
				assert.Equal(t, "DISPLAY_NAME_MISMATCH", detection.Type)
				assert.Equal(t, tt.expectedConf, detection.Confidence)
				assert.Contains(t, detection.Evidence, "executive title")
			} else {
				assert.Nil(t, detection, "Expected no detection but got one")
			}
		})
	}
}
