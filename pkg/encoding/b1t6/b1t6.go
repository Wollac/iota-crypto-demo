// Package b1t6 implements the b1t6 encoding encoding as specified by IOTA Protocol RFC-0015.
package b1t6

import (
	"errors"
	"fmt"
	"math"
	"strings"

	"github.com/iotaledger/iota.go/consts"
	"github.com/iotaledger/iota.go/trinary"
)

const (
	tritsPerByte = 6
)

// EncodedLen returns the trit-length of an encoding of n source bytes.
func EncodedLen(n int) int { return n * tritsPerByte }

// Encode encodes src into EncodedLen(len(src)) trits.
// Encode implements the b1t6 encoding converting a bit string into ternary.
func Encode(src []byte) trinary.Trits {
	return trinary.MustTrytesToTrits(EncodeToTrytes(src))
}

// EncodeToTrytes encodes src into trytes.
func EncodeToTrytes(src []byte) trinary.Trytes {
	var dst strings.Builder
	dst.Grow(EncodedLen(len(src)) / consts.TritsPerTryte)

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

var (
	// ErrInvalidLength reports an attempt to decode an input which has a trit-length that is not a multiple of 6.
	ErrInvalidLength = errors.New("length must be a multiple of 6 trits")
	// ErrInvalidTrits reports an attempt to decode an input that contains an invalid trit sequence.
	ErrInvalidTrits = errors.New("invalid trits")
)

// DecodedLen returns the byte-length of a decoding of n source trits.
func DecodedLen(n int) int { return n / tritsPerByte }

// Decode decodes src into DecodedLen(len(src)) bytes.
// Decode expects that src contains a valid b1t6 encoding and that src has a length that is a multiple of 6,
// it returns an error otherwise. If src does not contain valid trit-values the behavior of Decode is undefined.
func Decode(src trinary.Trits) ([]byte, error) {
	if len(src)%tritsPerByte != 0 {
		return nil, ErrInvalidLength
	}
	return DecodeTrytes(trinary.MustTritsToTrytes(src))
}

// DecodeTrytes returns the bytes represented by the t6b1 encoded trytes.
// DecodeTrytes expects that src contains a valid b1t6 encoding and that src has even length,
// it returns an error otherwise. If src does not contain valid trit-values the behavior of DecodeTrytes is undefined.
func DecodeTrytes(src trinary.Trytes) ([]byte, error) {
	if len(src)%(tritsPerByte/consts.TritsPerTryte) != 0 {
		return nil, ErrInvalidLength
	}
	dst := make([]byte, DecodedLen(len(src)*consts.TritsPerTryte))
	for i := 1; i < len(src); i += 2 {
		v := int(trinary.MustTryteToTryteValue(src[i-1])) + int(trinary.MustTryteToTryteValue(src[i]))*consts.TryteRadix
		if v < math.MinInt8 || v > math.MaxInt8 {
			return nil, fmt.Errorf("%w: %s", ErrInvalidTrits, src[i-1:i+1])
		}
		dst[i/2] = byte(v)
	}
	return dst, nil
}
