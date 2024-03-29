// Package hexutil implements hexadecimal encoding.
package hexutil

import (
	"encoding/hex"
)

// Bytes is a slice of bytes that marshals/unmarshals as a string in hexadecimal encoding.
type Bytes []byte

// Bytes returns the underlying byte slice.
func (b Bytes) Bytes() []byte {
	return b
}

// MarshalText implements the encoding.TextMarshaler interface.
func (b Bytes) MarshalText() ([]byte, error) {
	dst := make([]byte, hex.EncodedLen(len(b)))
	hex.Encode(dst, b)
	return dst, nil
}

// UnmarshalText implements the encoding.TextUnmarshaler interface.
func (b *Bytes) UnmarshalText(text []byte) (err error) {
	dec := make([]byte, hex.DecodedLen(len(text)))
	if _, err = hex.Decode(dec, text); err != nil {
		return err
	}
	*b = dec
	return
}

// String returns the hex encoding of b.
func (b Bytes) String() string {
	return hex.EncodeToString(b)
}

// MustDecodeString returns the bytes represented by the hexadecimal string s.
func MustDecodeString(s string) []byte {
	dst, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return dst
}
