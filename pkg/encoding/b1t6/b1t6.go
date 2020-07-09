// Package b1t6 implements the b1t6 encoding encoding as specified by IOTA Protocol RFC-0015.
package b1t6

import (
	"fmt"
	"math"
	"strings"

	"github.com/iotaledger/iota.go/consts"
	"github.com/iotaledger/iota.go/trinary"
)

// EncodedLen returns the length of an encoding of n source bytes.
// Specifically, it returns n * 2.
func EncodedLen(n int) int { return n * 2 }

// Encode encodes src into EncodedLen(len(src)) trytes.
// Encode implements the b1t6 encoding converting a bit string into its ternary
// representation by representing one byte as two trytes.
func Encode(src []byte) trinary.Trytes {
	var dst strings.Builder
	dst.Grow(len(src) * 2)

	for i := range src {
		// convert the signed byte value to two dst.
		// this is equivalent to: IntToTrytes(int8(src[i]), 2)
		v := int(int8(src[i])) + (consts.TryteRadix/2)*consts.TryteRadix + consts.TryteRadix/2 // make un-balanced
		quo, rem := v/consts.TryteRadix, v%consts.TryteRadix
		dst.WriteByte(trinary.TryteValueToTyteLUT[rem])
		dst.WriteByte(trinary.TryteValueToTyteLUT[quo])
	}
	return dst.String()
}

// DecodedLen returns the length of a decoding of n source trytes.
// Specifically, it returns n / 2.
func DecodedLen(n int) int { return n / 2 }

// Decode decodes src into DecodedLen(len(src)) bytes.
// Decode expects that src contains a valid b1t6 encoding and that src has even length.
// If the input is malformed, Decode returns an error.
func Decode(src trinary.Trytes) ([]byte, error) {
	if len(src)%2 != 0 {
		return nil, fmt.Errorf("%w: length must be even", consts.ErrInvalidTrytesLength)
	}
	dst := make([]byte, len(src)/2)
	for i := 1; i < len(src); i += 2 {
		a, ok := tryteToTryteValue(src[i-1])
		if !ok {
			return nil, fmt.Errorf("%w: at index %d (tryte: %c)", consts.ErrInvalidTrytes, i-1, src[i-1])
		}
		b, ok := tryteToTryteValue(src[i])
		if !ok {
			return nil, fmt.Errorf("%w: at index %d (tryte: %c)", consts.ErrInvalidTrytes, i, src[i])
		}
		v := a + b*consts.TryteRadix
		if v < math.MinInt8 || v > math.MaxInt8 {
			return nil, fmt.Errorf("%w: at index %d (trytes: %s)", consts.ErrInvalidTrytes, i-1, src[i-1:i+1])
		}
		dst[i/2] = byte(v)
	}
	return dst, nil
}

func tryteToTryteValue(t byte) (int, bool) {
	idx := int(t - '9')
	if idx < 0 || idx >= len(trinary.TryteToTryteValueLUT) {
		return 0, false
	}
	return int(trinary.TryteToTryteValueLUT[idx]), true
}
