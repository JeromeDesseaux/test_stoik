package detection

import (
	"regexp"
	"strings"

	"github.com/stoik/email-security/internal/domain"
)

// isInternalDomain checks if a domain belongs to the organization
func isInternalDomain(domain string, internalDomains []string) bool {
	for _, internal := range internalDomains {
		if domain == internal {
			return true
		}
	}
	return false
}

// extractDomain extracts the domain from an email address
func extractDomain(email string) string {
	parts := strings.Split(email, "@")
	if len(parts) != 2 {
		return "" // Malformed email address
	}
	return strings.ToLower(parts[1])
}

// ValidateEmail performs basic email format validation
func ValidateEmail(email string) bool {
	emailRegex := regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)
	return emailRegex.MatchString(email)
}

// levenshteinDistance calculates the edit distance between two strings
func levenshteinDistance(s1, s2 string) int {
	// Base cases: if either string is empty, distance is the other string's length
	if len(s1) == 0 {
		return len(s2)
	}
	if len(s2) == 0 {
		return len(s1)
	}

	// Create DP table: matrix[i][j] = distance between s1[0:i] and s2[0:j]
	matrix := make([][]int, len(s1)+1)
	for i := range matrix {
		matrix[i] = make([]int, len(s2)+1)
	}

	// Initialize first row and column
	// matrix[i][0] represents deleting all i characters from s1
	// matrix[0][j] represents inserting all j characters from s2
	for i := 0; i <= len(s1); i++ {
		matrix[i][0] = i
	}
	for j := 0; j <= len(s2); j++ {
		matrix[0][j] = j
	}

	// Fill DP table using recurrence relation
	for i := 1; i <= len(s1); i++ {
		for j := 1; j <= len(s2); j++ {
			// Cost of substitution: 0 if characters match, 1 otherwise
			cost := 1
			if s1[i-1] == s2[j-1] {
				cost = 0
			}

			// Take minimum of three operations:
			matrix[i][j] = min(
				matrix[i-1][j]+1,      // Deletion: remove char from s1
				matrix[i][j-1]+1,      // Insertion: add char to s1
				matrix[i-1][j-1]+cost, // Substitution: replace char in s1
			)
		}
	}

	// Bottom-right cell contains the final distance
	return matrix[len(s1)][len(s2)]
}

// hasUrgencyLanguage checks if email contains urgency keywords
// This is a simplified check - the full UrgencyFinancialStrategy provides more detail
func hasUrgencyLanguage(email domain.Email) bool {
	text := strings.ToLower(email.Subject + " " + email.BodyPreview)
	urgencyKeywords := []string{"urgent", "immediately", "asap", "right away", "today"}
	return containsAny(text, urgencyKeywords)
}

// containsAny checks if text contains any of the keywords
func containsAny(text string, keywords []string) bool {
	for _, keyword := range keywords {
		if strings.Contains(text, keyword) {
			return true
		}
	}
	return false
}
