package detection

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestLevenshteinDistance(t *testing.T) {
	tests := []struct {
		s1       string
		s2       string
		expected int
	}{
		{"", "", 0},
		{"abc", "abc", 0},
		{"abc", "ab", 1},
		{"microsoft", "micros0ft", 1},
		{"paypal", "paypa1", 1},
		{"google", "g00gle", 2},
	}

	for _, tt := range tests {
		t.Run(tt.s1+" vs "+tt.s2, func(t *testing.T) {
			distance := levenshteinDistance(tt.s1, tt.s2)
			assert.Equal(t, tt.expected, distance)
		})
	}
}
