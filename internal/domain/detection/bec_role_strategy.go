package detection

import (
	"fmt"
	"strings"

	"github.com/stoik/email-security/internal/domain"
)

// BECRoleStrategy detects Business Email Compromise attempts targeting high-value roles
// Supports both English and French (France-compliant) detection patterns
type BECRoleStrategy struct{}

// NewBECRoleStrategy creates a new BEC role targeting detection strategy
func NewBECRoleStrategy() *BECRoleStrategy {
	return &BECRoleStrategy{}
}

// Name returns the strategy name
func (s *BECRoleStrategy) Name() string {
	return "BEC Role Targeting"
}

// Detect identifies BEC attempts targeting high-value roles
func (s *BECRoleStrategy) Detect(email domain.Email, recipient *domain.User, context *DetectionContext) *domain.Detection {
	// Can only detect role-based targeting if we know the recipient
	if recipient == nil || recipient.Role == "" {
		return nil
	}

	role := strings.ToLower(recipient.Role)
	senderDomain := extractDomain(email.SenderEmail)
	isExternal := !isInternalDomain(senderDomain, context.InternalDomains)

	// Only flag if sender is external
	// Internal emails to executives are normal business communication
	if !isExternal {
		return nil
	}

	// Define high-value targets for BEC
	cSuiteRoles := []string{
		// English roles
		"ceo", "cfo", "cto", "coo", "president", "chief", "vice president", "vp",
		// French roles
		"pdg", "président directeur général", "directeur général", "dg",
		"daf", "directeur administratif et financier", "directeur financier",
		"dsi", "directeur des systèmes d'information",
		"directeur", "direction générale",
	}
	financeRoles := []string{
		// English roles
		"finance", "accounting", "treasurer", "controller", "payroll",
		// French roles
		"comptabilité", "comptable", "trésorier", "trésorerie",
		"contrôleur de gestion", "contrôleur financier",
		"responsable financier", "responsable comptable",
		"service comptable", "paie",
	}
	hrRoles := []string{
		// English roles
		"hr", "human resources", "recruiting", "talent",
		// French roles
		"drh", "directeur des ressources humaines", "ressources humaines",
		"rh", "responsable rh", "responsable ressources humaines",
		"recrutement", "gestionnaire paie", "service rh",
	}

	isCsuite := containsAny(role, cSuiteRoles)
	isFinance := containsAny(role, financeRoles)
	isHR := containsAny(role, hrRoles)

	// If not a high-value target, no detection
	if !isCsuite && !isFinance && !isHR {
		return nil
	}

	// Check for financial urgency keywords in subject + body
	text := strings.ToLower(email.Subject + " " + email.BodyPreview)

	// Urgency keywords
	urgencyKeywords := []string{
		// English
		"urgent", "immediately", "asap", "today", "right away", "now",
		// French
		"urgent", "immédiatement", "rapidement", "aujourd'hui",
		"tout de suite", "au plus vite", "dans l'immédiat",
		"sans délai", "prioritaire", "en urgence",
	}

	// Wire transfer and payment keywords
	wireTransferKeywords := []string{
		// English
		"wire transfer", "payment", "invoice", "bank account", "routing", "iban", "swift",
		// French
		"virement", "virement bancaire", "paiement", "facture",
		"compte bancaire", "rib", "relevé d'identité bancaire",
		"iban", "bic", "swift", "coordonnées bancaires",
		"ordre de virement", "transfert de fonds",
	}

	// Payroll/tax document keywords
	payrollDocKeywords := []string{
		// English (US)
		"tax form", "payroll",
		// French
		"bulletin de paie", "bulletin de salaire", "fiche de paie",
		"numéro de sécurité sociale", "n° sécurité sociale",
		"cotisations sociales", "déclaration de revenus",
		"dsn", "déclaration sociale nominative",
		"attestation fiscale", "salaires",
	}

	hasUrgency := containsAny(text, urgencyKeywords)
	hasWireTransfer := containsAny(text, wireTransferKeywords)
	hasPayrollDoc := containsAny(text, payrollDocKeywords)

	// Calculate confidence based on role + content combination
	// Higher confidence for more specific targeting patterns

	// CRITICAL: C-suite + urgent wire transfer = classic CEO fraud
	if isCsuite && hasUrgency && hasWireTransfer {
		return &domain.Detection{
			Type:       "BEC_CSUITE_TARGETING",
			Confidence: 0.90,
			Evidence: fmt.Sprintf(
				"Executive recipient (%s) + external sender + urgent wire transfer request (potential CEO fraud/Fraude au président)",
				recipient.Role,
			),
		}
	}

	// HIGH: Finance + wire transfer = invoice fraud attempt
	if isFinance && hasWireTransfer {
		return &domain.Detection{
			Type:       "BEC_FINANCE_TARGETING",
			Confidence: 0.85,
			Evidence: fmt.Sprintf(
				"Finance role (%s) + external sender + payment/wire transfer language (potential invoice fraud)",
				recipient.Role,
			),
		}
	}

	// HIGH: HR + payroll document request = payroll/tax document phishing
	if isHR && hasPayrollDoc {
		return &domain.Detection{
			Type:       "BEC_HR_PAYROLL_SCAM",
			Confidence: 0.80,
			Evidence: fmt.Sprintf(
				"HR role (%s) + external sender + payroll/tax document request (W-2/bulletin de paie phishing)",
				recipient.Role,
			),
		}
	}

	// MEDIUM: Generic high-value target with urgency
	// Less specific but still suspicious
	if (isCsuite || isFinance || isHR) && hasUrgency {
		return &domain.Detection{
			Type:       "BEC_HIGH_VALUE_TARGET",
			Confidence: 0.70,
			Evidence: fmt.Sprintf(
				"High-value role (%s) + external sender + urgent language",
				recipient.Role,
			),
		}
	}

	return nil
}
