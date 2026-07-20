package controller

import (
	"errors"
	"unicode"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"
)

const (
	maxLabelBytes   = 256
	maxLabelScalars = 80
)

// CanonicalLabel validates the closed Unicode profile and returns its NFC form.
func CanonicalLabel(raw string) (string, error) {
	if raw == "" || len(raw) > maxLabelBytes || !utf8.ValidString(raw) {
		return "", errors.New("label byte length or UTF-8 is invalid")
	}
	canonical := norm.NFC.String(raw)
	if canonical == "" || len(canonical) > maxLabelBytes || !utf8.ValidString(canonical) {
		return "", errors.New("canonical label byte length is invalid")
	}
	runes := []rune(canonical)
	if len(runes) == 0 || len(runes) > maxLabelScalars {
		return "", errors.New("label scalar count is invalid")
	}
	if !letterOrDigit(runes[0]) || !letterOrDigit(runes[len(runes)-1]) {
		return "", errors.New("label must start and end with a letter or digit")
	}
	previousWasLetterOrMark := false
	previousWasSpace := false
	for _, value := range runes {
		switch {
		case unicode.IsLetter(value):
			previousWasLetterOrMark = true
			previousWasSpace = false
		case unicode.IsMark(value):
			if !previousWasLetterOrMark {
				return "", errors.New("combining mark must follow a letter or mark")
			}
			previousWasLetterOrMark = true
			previousWasSpace = false
		case unicode.Is(unicode.Nd, value):
			previousWasLetterOrMark = false
			previousWasSpace = false
		case value == ' ':
			if previousWasSpace {
				return "", errors.New("consecutive spaces are forbidden")
			}
			previousWasLetterOrMark = false
			previousWasSpace = true
		case value == '-' || value == '_' || value == '.' || value == '\'' || value == '(' || value == ')':
			previousWasLetterOrMark = false
			previousWasSpace = false
		default:
			return "", errors.New("label contains a character outside the positive list")
		}
	}
	return canonical, nil
}

func letterOrDigit(value rune) bool {
	return unicode.IsLetter(value) || unicode.Is(unicode.Nd, value)
}
