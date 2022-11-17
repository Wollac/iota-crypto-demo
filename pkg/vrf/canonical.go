package vrf

import (
	"bytes"
	"errors"

	"filippo.io/edwards25519"
)

var ErrNonCanonical = errors.New("non canonical point encoding")

var nonCanonicalSignBytes = [...][]byte{
	// y = 1, sign-"
	{
		0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80,
	},
	// y = p-1, sign-
	{
		0xec, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	},
}

// newPointFromCanonicalBytes creates a new point from the encoding x.
// It compatible with string_to_point from RFC 8032 and returns an error if x is non-canonical.
func newPointFromCanonicalBytes(x []byte) (*edwards25519.Point, error) {
	if !isCanonicalY(x) {
		return nil, ErrNonCanonical
	}
	// test for the two cases with a canonically encoded y with a non-canonical sign bit
	if bytes.Equal(x, nonCanonicalSignBytes[0]) || bytes.Equal(x, nonCanonicalSignBytes[1]) {
		return nil, ErrNonCanonical
	}
	return new(edwards25519.Point).SetBytes(x)
}

// isCanonicalY checks whether the Y-part of x represents a canonical encoding using the succeed-fast algorithm from
// the "Taming the many EdDSAs" paper.
func isCanonicalY(x []byte) bool {
	_ = x[31]
	if x[0] < 237 {
		return true
	}
	for i := 1; i <= 30; i++ {
		if x[i] != 255 {
			return true
		}
	}
	return x[31]|128 != 255
}
