package detection

import (
	"testing"

	"github.com/stoik/email-security/internal/domain"
	"github.com/stretchr/testify/assert"
)

func TestReplyToStrategy_Detect(t *testing.T) {
	context := NewDetectionContext([]string{}, []string{})

	tests := []struct {
		name            string
		senderEmail     string
		replyTo         string
		expectDetection bool
	}{
		{
			name:            "Reply-To same as sender - no detection",
			senderEmail:     "user@company.com",
			replyTo:         "user@company.com",
			expectDetection: false,
		},
		{
			name:            "Reply-To redirects to Gmail - should detect",
			senderEmail:     "ceo@company.com",
			replyTo:         "attacker@gmail.com",
			expectDetection: true,
		},
		{
			name:            "Reply-To to different corporate domain - less suspicious",
			senderEmail:     "user@company.com",
			replyTo:         "user@corporate.com",
			expectDetection: false,
		},
		{
			name:            "Empty Reply-To - no detection",
			senderEmail:     "user@company.com",
			replyTo:         "",
			expectDetection: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			email := domain.Email{
				SenderEmail: tt.senderEmail,
				Headers: map[string]string{
					"Reply-To": tt.replyTo,
				},
			}
			detection := NewReplyToStrategy().Detect(email, nil, context)

			if tt.expectDetection {
				assert.NotNil(t, detection, "Expected Reply-To mismatch detection")
				assert.Equal(t, "REPLY_TO_MISMATCH", detection.Type)
			} else {
				assert.Nil(t, detection, "Expected no detection")
			}
		})
	}
}
