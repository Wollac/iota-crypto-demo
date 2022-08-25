// Package b1t8 implements the b1t8 encoding which uses 8 trits to encode each byte.
package b1t8

import (
	"errors"
	"fmt"

	"github.com/iotaledger/iota.go/trinary"
)

const (
	tritsPerByte = 8
)

// EncodedLen returns the trit-length of an encoding of n source bytes.
func EncodedLen(n int) int { return n * tritsPerByte }

// Encode encodes src into EncodedLen(len(src)) trits of dst. As a convenience, it returns the number of trits written,
// but this value is always EncodedLen(len(src)).
// Encode implements the b1t8 encoding converting a bit string into ternary.
func Encode(dst trinary.Trits, src []byte) int {
	for _, b := range src {
		_ = dst[7] // early bounds check to guarantee safety of writes below
		dst[0] = int8(b & 0x01 >> 0)
		dst[1] = int8(b & 0x02 >> 1)
		dst[2] = int8(b & 0x04 >> 2)
		dst[3] = int8(b & 0x08 >> 3)
		dst[4] = int8(b & 0x10 >> 4)
		dst[5] = int8(b & 0x20 >> 5)
		dst[6] = int8(b & 0x40 >> 6)
		dst[7] = int8(b & 0x80 >> 7)

		dst = dst[8:]
	}
	return EncodedLen(len(src))
}

var (
	// ErrInvalidLength reports an attempt to decode an input which has a trit-length that is not a multiple of 8.
	ErrInvalidLength = errors.New("length must be a multiple of 8 trits")
	// ErrInvalidTrit reports an attempt to decode an input that contains an invalid trit sequence.
	ErrInvalidTrit = errors.New("invalid trits")
)

// DecodedLen returns the byte-length of a decoding of n source trits.
func DecodedLen(n int) int { return n / tritsPerByte }

// Decode decodes src into DecodedLen(len(src)) bytes of dst and returns the actual number of bytes written.
// Decode expects that src contains a valid b1t8 encoding and that src has a length that is a multiple of 8,
// it returns an error otherwise.
// If the input is malformed, Decode returns the number of bytes decoded before the error.
func Decode(dst []byte, src trinary.Trits) (int, error) {
	i := 0
	for len(src) >= tritsPerByte {
		var b byte
		for j := 0; j < tritsPerByte; j++ {
			trit := uint(src[j])
			if trit > 1 {
				return i, fmt.Errorf("%w: %d", ErrInvalidTrit, src[j])
			}
			b |= byte(trit << j)
		}
		dst[i] = b
		src = src[tritsPerByte:]
		i++
	}
	if len(src) > 0 {
		// Check for invalid char before reporting bad length,
		// since the invalid trit (if present) is an earlier problem.
		for _, t := range src {
			if byte(t) > 1 {
				return i, fmt.Errorf("%w: %d", ErrInvalidTrit, t)
			}
		}
		return i, ErrInvalidLength
	}
	return i, nil
}
