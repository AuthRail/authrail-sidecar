package sidecar

import (
	"encoding/json"
	"regexp"
	"strings"
)

const emailRedactionHandlerID = "authrail_redact_email_v1"
const emailRedactionHandlerVersion = "9773bce1f804773de4e773f4fedbc3f8a15785d26e70e49ad7b600eb631ea49d"
const paymentCardRedactionHandlerID = "authrail_redact_payment_card_v1"
const paymentCardRedactionHandlerVersion = "01c828b26465d66ad89cb6a350c82d9afa1d8673ee8e167acfc33bde27c1535b"
const withholdFieldHandlerID = "authrail_withhold_field_v1"
const withholdFieldHandlerVersion = "3ebd6aaea66cbd30459938a624b0f74d6bea612e28d6638273a67145b2fe5555"

var emailAddressV1 = regexp.MustCompile(`[A-Za-z0-9][A-Za-z0-9._%+-]{0,63}@[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+`)
var paymentCardRunV1 = regexp.MustCompile(`[0-9](?:[0-9 -]*[0-9])?`)

type disclosureProtection struct {
	Field   field
	Profile string
}

func validSensitiveComparison(node condition) (string, bool) {
	var profile string
	if node.Right.Kind != "literal" || json.Unmarshal(node.Right.Value, &profile) != nil {
		return "", false
	}
	return profile, profile == "email_address_v1" || profile == "payment_card_v1"
}

// Fixed formats deliberately avoid guessing whether arbitrary text is personal data.
func sensitiveFormatV1(profile, text string) bool {
	switch profile {
	case "credential_formats_v1":
		return credentialFormatV1(text)
	case "email_address_v1":
		for _, index := range emailAddressV1.FindAllStringIndex(text, -1) {
			candidate := text[index[0]:index[1]]
			if index[0] > 0 && emailBoundaryByte(text[index[0]-1], true) || index[1] < len(text) && emailBoundaryByte(text[index[1]], false) {
				continue
			}
			at := strings.IndexByte(candidate, '@')
			local := candidate[:at]
			tld := candidate[strings.LastIndexByte(candidate, '.')+1:]
			if len(candidate) > 254 || len(local) > 64 || strings.Contains(local, "..") || strings.HasSuffix(local, ".") || len(tld) < 2 || len(tld) > 63 {
				continue
			}
			letters := true
			for _, char := range []byte(tld) {
				letters = letters && (char >= 'a' && char <= 'z' || char >= 'A' && char <= 'Z')
			}
			if letters {
				return true
			}
		}
	case "payment_card_v1":
		for _, run := range paymentCardRunV1.FindAllString(text, -1) {
			digits := strings.NewReplacer(" ", "", "-", "").Replace(run)
			if len(digits) < 13 || len(digits) > 19 || strings.Trim(digits, digits[:1]) == "" {
				continue
			}
			sum, double := 0, false
			for i := len(digits) - 1; i >= 0; i-- {
				digit := int(digits[i] - '0')
				if double {
					digit *= 2
					if digit > 9 {
						digit -= 9
					}
				}
				sum += digit
				double = !double
			}
			if sum%10 == 0 {
				return true
			}
		}
	}
	return false
}

func emailBoundaryByte(char byte, before bool) bool {
	return char >= 'a' && char <= 'z' || char >= 'A' && char <= 'Z' || char >= '0' && char <= '9' || char == '_' || char == '@' || char == '-' || before && (char == '.' || char == '%' || char == '+')
}

func builtinGuardVersion(id string) (string, bool) {
	switch id {
	case credentialRedactionHandlerID:
		return credentialRedactionHandlerVersion, true
	case emailRedactionHandlerID:
		return emailRedactionHandlerVersion, true
	case paymentCardRedactionHandlerID:
		return paymentCardRedactionHandlerVersion, true
	case withholdFieldHandlerID:
		return withholdFieldHandlerVersion, true
	default:
		return "", false
	}
}

func builtinGuardProfile(id string) string {
	switch id {
	case credentialRedactionHandlerID:
		return "credential_formats_v1"
	case emailRedactionHandlerID:
		return "email_address_v1"
	case paymentCardRedactionHandlerID:
		return "payment_card_v1"
	case withholdFieldHandlerID:
		return "withhold_field_v1"
	default:
		return ""
	}
}

func builtinGuardOutputValid(id, text string) bool {
	profile := builtinGuardProfile(id)
	if profile == "withhold_field_v1" {
		return text == "[WITHHELD]"
	}
	return profile == "" || !sensitiveFormatV1(profile, text)
}
