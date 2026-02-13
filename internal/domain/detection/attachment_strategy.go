package detection

import (
	"fmt"
	"strings"

	"github.com/stoik/email-security/internal/domain"
)

// AttachmentStrategy detects suspicious attachment types
//
// Attack pattern: Malicious attachments are the #1 malware delivery method
type AttachmentStrategy struct{}

// NewAttachmentStrategy creates a new suspicious attachments detection strategy
func NewAttachmentStrategy() *AttachmentStrategy {
	return &AttachmentStrategy{}
}

// Name returns the strategy name
func (s *AttachmentStrategy) Name() string {
	return "Suspicious Attachments"
}

// Detect checks for high-risk attachment types
func (s *AttachmentStrategy) Detect(email domain.Email, recipient *domain.User, context *DetectionContext) *domain.Detection {
	if !email.HasAttachments {
		return nil
	}

	// HIGH RISK: Executables and scripts
	// These can run arbitrary code on the victim's machine
	highRiskExtensions := []string{
		".exe", ".scr", ".bat", ".cmd", ".com", ".pif",
		".vbs", ".js", ".jar", ".msi", ".app",
	}

	// MEDIUM RISK: Office documents with macro support
	// Macros can download and execute malware
	mediumRiskExtensions := []string{
		".doc", ".xls", ".xlsm", ".docm", ".pptm",
	}

	for _, name := range email.AttachmentNames {
		filename := strings.ToLower(name)

		// Check for high-risk extensions
		for _, ext := range highRiskExtensions {
			if strings.HasSuffix(filename, ext) {
				return &domain.Detection{
					Type:       "HIGH_RISK_ATTACHMENT",
					Confidence: 0.90,
					Evidence:   fmt.Sprintf("High-risk attachment type: %s", name),
				}
			}
		}

		// Check for double extension trick (e.g., invoice.pdf.exe)
		// Legitimate files rarely have multiple extensions
		dotCount := strings.Count(filename, ".")
		if dotCount > 1 {
			return &domain.Detection{
				Type:       "SUSPICIOUS_ATTACHMENT_NAME",
				Confidence: 0.85,
				Evidence:   fmt.Sprintf("Suspicious attachment name (double extension): %s", name),
			}
		}

		// Medium risk if combined with urgent language
		// Legitimate senders don't typically combine urgent requests with macro documents
		for _, ext := range mediumRiskExtensions {
			if strings.HasSuffix(filename, ext) {
				// Check if email also has urgency language
				if hasUrgencyLanguage(email) {
					return &domain.Detection{
						Type:       "MEDIUM_RISK_ATTACHMENT_WITH_URGENCY",
						Confidence: 0.70,
						Evidence:   fmt.Sprintf("Medium-risk attachment + urgent language: %s", name),
					}
				}
			}
		}
	}

	return nil
}
