package gokeystorev4

import (
	"strings"
	"unicode"

	"golang.org/x/text/unicode/norm"
)

// ProcessPassword encodes password in NFKD form and removes all control characters
func ProcessPassword(password string) []byte {
	password = norm.NFKD.String(password)
	password = strings.Map(func(r rune) rune {
		if !unicode.IsControl(r) {
			return r
		}
		return -1
	}, password)

	return []byte(password)
}
