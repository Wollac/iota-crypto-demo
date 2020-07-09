package t5b1

import (
	"fmt"

	"github.com/iotaledger/iota.go/consts"
	"github.com/iotaledger/iota.go/trinary"
)

const tritsPerByte = 5

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

// EncodedLen returns the length of an encoding of n source bytes.
func EncodedLen(n int) int { return n / tritsPerByte }

// Encode encodes src into EncodedLen(len(src)) bytes.
// Encode implements the t5b1 encoding converting a trit string into binary.
// If the length of src is not a multiple of 5 an error is returned.
func Encode(src trinary.Trits) ([]byte, error) {
	if len(src)%tritsPerByte != 0 {
		return nil, fmt.Errorf("%w: length must be a multiple of 5", consts.ErrInvalidTritsLength)
	}

	dst := make([]byte, EncodedLen(len(src)))
	for i := range dst {
		// bounds check hints to compiler
		tmp := src[i*5:]
		_ = tmp[4]

		v := int(tmp[0]) + int(tmp[1])*3 + int(tmp[2])*9 + int(tmp[3])*27 + int(tmp[4])*81
		dst[i] = byte(v)
	}
	return dst, nil
}

// EncodeToTrytes encodes src into bytes.
func EncodeTrytes(src trinary.Trytes) ([]byte, error) {
	trits, err := trinary.TrytesToTrits(src)
	if err != nil {
		return nil, err
	}
	rem := len(trits) % tritsPerByte
	if rem == 0 {
		return Encode(trits)
	}
	if !hasTrailingZeros(trits, rem) {
		return nil, consts.ErrInvalidTrytesLength
	}
	return Encode(trits[:len(trits)-rem])
}

// DecodedLen returns the length of a decoding of n source trits.
func DecodedLen(n int) int { return n * tritsPerByte }

// Decode decodes src into DecodedLen(len(src)) trits.
// If src does not contain a valid t5b1 encoding, an error is returned.
func Decode(src []byte) (trinary.Trits, error) {
	dst := make(trinary.Trits, DecodedLen(len(src)))
	for i, b := range src {
		if int8(b) < -121 || int8(b) > 121 {
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

// DecodeToTrytes returns the trytes represented by the t6b1 encoded trytes.
// If the input is malformed, DecodeTrytes returns an error.
func DecodeToTrytes(src []byte) (trinary.Trytes, error) {
	trits, err := Decode(src)
	if err != nil {
		return "", err
	}
	rem := len(trits) % consts.TritsPerTryte
	if rem > 0 {
		trits = trinary.MustPadTrits(trits, len(trits)+consts.TritsPerTryte-rem)
	}
	return trinary.MustTritsToTrytes(trits), nil
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
