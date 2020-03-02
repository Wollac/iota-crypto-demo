package bip39

import (
	"strings"

	"golang.org/x/text/unicode/norm"
)

// Mnemonic is a slice of mnemonic words, with extra utility methods on top.
type Mnemonic []string

// ParseMnemonic parses s as white space separated list of mnemonic words.
func ParseMnemonic(s string) Mnemonic {
	normalized := norm.NFKD.String(s)
	return strings.Fields(normalized)
}

// String will return all the words composing the mnemonic sentence as a single string of space separated words.
func (ms Mnemonic) String() string {
	return strings.Join(ms, " ")
}

// MarshalText implements the encoding.TextMarshaler interface.
func (ms Mnemonic) MarshalText() ([]byte, error) {
	return []byte(ms.String()), nil
}

// UnmarshalText implements the encoding.TextUnmarshaler interface.
func (ms *Mnemonic) UnmarshalText(text []byte) error {
	*ms = ParseMnemonic(string(text))
	return nil
}
