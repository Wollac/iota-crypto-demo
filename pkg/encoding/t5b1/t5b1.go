// Package t5b1 implements the t5b1 encoding encoding which uses one byte to represent each 5-trit group.
package t5b1

import (
	"errors"
	"fmt"

	"github.com/iotaledger/iota.go/consts"
	"github.com/iotaledger/iota.go/trinary"
)

const (
	tritsPerByte  = 5
	maxGroupValue = 1 + 3 + 9 + 27 + 81
	minGroupValue = -maxGroupValue
)

// lookup table to unpack a byte into 5 trits.
var tritsLUT = [256][tritsPerByte]int8{
	{0, 0, 0, 0, 0}, {1, 0, 0, 0, 0}, {-1, 1, 0, 0, 0}, {0, 1, 0, 0, 0}, {1, 1, 0, 0, 0}, {-1, -1, 1, 0, 0},
	{0, -1, 1, 0, 0}, {1, -1, 1, 0, 0}, {-1, 0, 1, 0, 0}, {0, 0, 1, 0, 0}, {1, 0, 1, 0, 0}, {-1, 1, 1, 0, 0},
	{0, 1, 1, 0, 0}, {1, 1, 1, 0, 0}, {-1, -1, -1, 1, 0}, {0, -1, -1, 1, 0}, {1, -1, -1, 1, 0}, {-1, 0, -1, 1, 0},
	{0, 0, -1, 1, 0}, {1, 0, -1, 1, 0}, {-1, 1, -1, 1, 0}, {0, 1, -1, 1, 0}, {1, 1, -1, 1, 0}, {-1, -1, 0, 1, 0},
	{0, -1, 0, 1, 0}, {1, -1, 0, 1, 0}, {-1, 0, 0, 1, 0}, {0, 0, 0, 1, 0}, {1, 0, 0, 1, 0}, {-1, 1, 0, 1, 0},
	{0, 1, 0, 1, 0}, {1, 1, 0, 1, 0}, {-1, -1, 1, 1, 0}, {0, -1, 1, 1, 0}, {1, -1, 1, 1, 0}, {-1, 0, 1, 1, 0},
	{0, 0, 1, 1, 0}, {1, 0, 1, 1, 0}, {-1, 1, 1, 1, 0}, {0, 1, 1, 1, 0}, {1, 1, 1, 1, 0}, {-1, -1, -1, -1, 1},
	{0, -1, -1, -1, 1}, {1, -1, -1, -1, 1}, {-1, 0, -1, -1, 1}, {0, 0, -1, -1, 1}, {1, 0, -1, -1, 1}, {-1, 1, -1, -1, 1},
	{0, 1, -1, -1, 1}, {1, 1, -1, -1, 1}, {-1, -1, 0, -1, 1}, {0, -1, 0, -1, 1}, {1, -1, 0, -1, 1}, {-1, 0, 0, -1, 1},
	{0, 0, 0, -1, 1}, {1, 0, 0, -1, 1}, {-1, 1, 0, -1, 1}, {0, 1, 0, -1, 1}, {1, 1, 0, -1, 1}, {-1, -1, 1, -1, 1},
	{0, -1, 1, -1, 1}, {1, -1, 1, -1, 1}, {-1, 0, 1, -1, 1}, {0, 0, 1, -1, 1}, {1, 0, 1, -1, 1}, {-1, 1, 1, -1, 1},
	{0, 1, 1, -1, 1}, {1, 1, 1, -1, 1}, {-1, -1, -1, 0, 1}, {0, -1, -1, 0, 1}, {1, -1, -1, 0, 1}, {-1, 0, -1, 0, 1},
	{0, 0, -1, 0, 1}, {1, 0, -1, 0, 1}, {-1, 1, -1, 0, 1}, {0, 1, -1, 0, 1}, {1, 1, -1, 0, 1}, {-1, -1, 0, 0, 1},
	{0, -1, 0, 0, 1}, {1, -1, 0, 0, 1}, {-1, 0, 0, 0, 1}, {0, 0, 0, 0, 1}, {1, 0, 0, 0, 1}, {-1, 1, 0, 0, 1},
	{0, 1, 0, 0, 1}, {1, 1, 0, 0, 1}, {-1, -1, 1, 0, 1}, {0, -1, 1, 0, 1}, {1, -1, 1, 0, 1}, {-1, 0, 1, 0, 1},
	{0, 0, 1, 0, 1}, {1, 0, 1, 0, 1}, {-1, 1, 1, 0, 1}, {0, 1, 1, 0, 1}, {1, 1, 1, 0, 1}, {-1, -1, -1, 1, 1},
	{0, -1, -1, 1, 1}, {1, -1, -1, 1, 1}, {-1, 0, -1, 1, 1}, {0, 0, -1, 1, 1}, {1, 0, -1, 1, 1}, {-1, 1, -1, 1, 1},
	{0, 1, -1, 1, 1}, {1, 1, -1, 1, 1}, {-1, -1, 0, 1, 1}, {0, -1, 0, 1, 1}, {1, -1, 0, 1, 1}, {-1, 0, 0, 1, 1},
	{0, 0, 0, 1, 1}, {1, 0, 0, 1, 1}, {-1, 1, 0, 1, 1}, {0, 1, 0, 1, 1}, {1, 1, 0, 1, 1}, {-1, -1, 1, 1, 1},
	{0, -1, 1, 1, 1}, {1, -1, 1, 1, 1}, {-1, 0, 1, 1, 1}, {0, 0, 1, 1, 1}, {1, 0, 1, 1, 1}, {-1, 1, 1, 1, 1},
	{0, 1, 1, 1, 1}, {1, 1, 1, 1, 1}, {0, 0, 0, 0, 0}, {0, 0, 0, 0, 0}, {0, 0, 0, 0, 0}, {0, 0, 0, 0, 0},
	{0, 0, 0, 0, 0}, {0, 0, 0, 0, 0}, {0, 0, 0, 0, 0}, {0, 0, 0, 0, 0}, {0, 0, 0, 0, 0}, {0, 0, 0, 0, 0},
	{0, 0, 0, 0, 0}, {0, 0, 0, 0, 0}, {0, 0, 0, 0, 0}, {-1, -1, -1, -1, -1}, {0, -1, -1, -1, -1}, {1, -1, -1, -1, -1},
	{-1, 0, -1, -1, -1}, {0, 0, -1, -1, -1}, {1, 0, -1, -1, -1}, {-1, 1, -1, -1, -1}, {0, 1, -1, -1, -1}, {1, 1, -1, -1, -1},
	{-1, -1, 0, -1, -1}, {0, -1, 0, -1, -1}, {1, -1, 0, -1, -1}, {-1, 0, 0, -1, -1}, {0, 0, 0, -1, -1}, {1, 0, 0, -1, -1},
	{-1, 1, 0, -1, -1}, {0, 1, 0, -1, -1}, {1, 1, 0, -1, -1}, {-1, -1, 1, -1, -1}, {0, -1, 1, -1, -1}, {1, -1, 1, -1, -1},
	{-1, 0, 1, -1, -1}, {0, 0, 1, -1, -1}, {1, 0, 1, -1, -1}, {-1, 1, 1, -1, -1}, {0, 1, 1, -1, -1}, {1, 1, 1, -1, -1},
	{-1, -1, -1, 0, -1}, {0, -1, -1, 0, -1}, {1, -1, -1, 0, -1}, {-1, 0, -1, 0, -1}, {0, 0, -1, 0, -1}, {1, 0, -1, 0, -1},
	{-1, 1, -1, 0, -1}, {0, 1, -1, 0, -1}, {1, 1, -1, 0, -1}, {-1, -1, 0, 0, -1}, {0, -1, 0, 0, -1}, {1, -1, 0, 0, -1},
	{-1, 0, 0, 0, -1}, {0, 0, 0, 0, -1}, {1, 0, 0, 0, -1}, {-1, 1, 0, 0, -1}, {0, 1, 0, 0, -1}, {1, 1, 0, 0, -1},
	{-1, -1, 1, 0, -1}, {0, -1, 1, 0, -1}, {1, -1, 1, 0, -1}, {-1, 0, 1, 0, -1}, {0, 0, 1, 0, -1}, {1, 0, 1, 0, -1},
	{-1, 1, 1, 0, -1}, {0, 1, 1, 0, -1}, {1, 1, 1, 0, -1}, {-1, -1, -1, 1, -1}, {0, -1, -1, 1, -1}, {1, -1, -1, 1, -1},
	{-1, 0, -1, 1, -1}, {0, 0, -1, 1, -1}, {1, 0, -1, 1, -1}, {-1, 1, -1, 1, -1}, {0, 1, -1, 1, -1}, {1, 1, -1, 1, -1},
	{-1, -1, 0, 1, -1}, {0, -1, 0, 1, -1}, {1, -1, 0, 1, -1}, {-1, 0, 0, 1, -1}, {0, 0, 0, 1, -1}, {1, 0, 0, 1, -1},
	{-1, 1, 0, 1, -1}, {0, 1, 0, 1, -1}, {1, 1, 0, 1, -1}, {-1, -1, 1, 1, -1}, {0, -1, 1, 1, -1}, {1, -1, 1, 1, -1},
	{-1, 0, 1, 1, -1}, {0, 0, 1, 1, -1}, {1, 0, 1, 1, -1}, {-1, 1, 1, 1, -1}, {0, 1, 1, 1, -1}, {1, 1, 1, 1, -1},
	{-1, -1, -1, -1, 0}, {0, -1, -1, -1, 0}, {1, -1, -1, -1, 0}, {-1, 0, -1, -1, 0}, {0, 0, -1, -1, 0}, {1, 0, -1, -1, 0},
	{-1, 1, -1, -1, 0}, {0, 1, -1, -1, 0}, {1, 1, -1, -1, 0}, {-1, -1, 0, -1, 0}, {0, -1, 0, -1, 0}, {1, -1, 0, -1, 0},
	{-1, 0, 0, -1, 0}, {0, 0, 0, -1, 0}, {1, 0, 0, -1, 0}, {-1, 1, 0, -1, 0}, {0, 1, 0, -1, 0}, {1, 1, 0, -1, 0},
	{-1, -1, 1, -1, 0}, {0, -1, 1, -1, 0}, {1, -1, 1, -1, 0}, {-1, 0, 1, -1, 0}, {0, 0, 1, -1, 0}, {1, 0, 1, -1, 0},
	{-1, 1, 1, -1, 0}, {0, 1, 1, -1, 0}, {1, 1, 1, -1, 0}, {-1, -1, -1, 0, 0}, {0, -1, -1, 0, 0}, {1, -1, -1, 0, 0},
	{-1, 0, -1, 0, 0}, {0, 0, -1, 0, 0}, {1, 0, -1, 0, 0}, {-1, 1, -1, 0, 0}, {0, 1, -1, 0, 0}, {1, 1, -1, 0, 0},
	{-1, -1, 0, 0, 0}, {0, -1, 0, 0, 0}, {1, -1, 0, 0, 0}, {-1, 0, 0, 0, 0},
}

// EncodedLen returns the byte-length of an encoding of n source trits.
func EncodedLen(n int) int { return (n + tritsPerByte - 1) / tritsPerByte }

// Encode encodes src into EncodedLen(len(src)) bytes.
// Encode implements the t5b1 encoding converting a trit string into binary.
// If the length of src is not a multiple of 5, it is padded with zeroes.
func Encode(src trinary.Trits) []byte {
	dst := make([]byte, EncodedLen(len(src)))
	for i := range dst {
		tmp := src[i*tritsPerByte:]
		// incomplete group
		if len(tmp) < tritsPerByte {
			var v int
			for j := len(tmp) - 1; j >= 0; j-- {
				v = v*3 + int(tmp[j])
			}
			dst[i] = byte(v)
			return dst
		}
		// common case, unrolled for extra performance
		v := int(tmp[0]) + int(tmp[1])*3 + int(tmp[2])*9 + int(tmp[3])*27 + int(tmp[4])*81
		dst[i] = byte(v)
	}
	return dst
}

// EncodeToTrytes encodes src into bytes.
// If the corresponding number of trits of src is not a multiple of 5, it is padded with zeroes.
func EncodeTrytes(src trinary.Trytes) []byte {
	return Encode(trinary.MustTrytesToTrits(src))
}

// ErrNonZeroPadding reports an attempt to decode an input without zero padding.
var ErrNonZeroPadding = errors.New("non-zero padding")

// DecodedLen returns the trit-length of a decoding of n source bytes.
func DecodedLen(n int) int { return n * tritsPerByte }

// Decode decodes src into DecodedLen(len(src)) trits.
// Decode expects that src contains a valid t5b1 encoding.
// If the input is malformed, Decode returns an error.
func Decode(src []byte) (trinary.Trits, error) {
	dst := make(trinary.Trits, DecodedLen(len(src)))
	for i, b := range src {
		if int8(b) < minGroupValue || int8(b) > maxGroupValue {
			return nil, fmt.Errorf("%w: at index %d (byte: %x)", consts.ErrInvalidByte, i, b)
		}
		// bounds check hints to compiler
		tmp := dst[i*5:]
		_ = tmp[4]
		tmp[0] = tritsLUT[b][0]
		tmp[1] = tritsLUT[b][1]
		tmp[2] = tritsLUT[b][2]
		tmp[3] = tritsLUT[b][3]
		tmp[4] = tritsLUT[b][4]
	}
	return dst, nil
}

// DecodeToTrytes decodes src into trytes.
// DecodeToTrytes expects that src contains a valid t5b1 encoding of a tryte-string.
// If the input is malformed or does not contain the correct zero padding, it returns an error.
func DecodeToTrytes(src []byte) (trinary.Trytes, error) {
	trits, err := Decode(src)
	if err != nil {
		return "", err
	}
	padLength := len(trits) % consts.TritsPerTryte
	if padLength == 0 {
		return trinary.MustTritsToTrytes(trits), nil
	}
	if !hasTrailingZeros(trits, padLength) {
		return "", ErrNonZeroPadding
	}
	return trinary.MustTritsToTrytes(trits[:len(trits)-padLength]), nil
}

// returns true if trits has at least n trailing zeroes
func hasTrailingZeros(trits trinary.Trits, n int) bool {
	i := len(trits) - n
	if i < 0 {
		return false
	}
	for ; i < len(trits); i++ {
		if trits[i] != 0 {
			return false
		}
	}
	return true
}
