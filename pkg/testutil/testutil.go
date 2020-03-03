package testutil

import (
	"encoding/hex"
)

// HexBytes is a slice of bytes that can be read and written in hex encoding.
type HexBytes []byte

// MarshalText implements the encoding.TextMarshaler interface.
func (h HexBytes) MarshalText() ([]byte, error) {
	return []byte(hex.EncodeToString(h)), nil
}

// UnmarshalText implements the encoding.TextUnmarshaler interface.
func (h *HexBytes) UnmarshalText(text []byte) (err error) {
	*h, err = hex.DecodeString(string(text))
	return
}
