package t5b1

import (
	"errors"
	"fmt"
	"math/rand"
	"strings"
	"testing"

	"github.com/iotaledger/iota.go/consts"
	"github.com/iotaledger/iota.go/trinary"
	"github.com/stretchr/testify/assert"
)

var encDecTest = []*struct {
	enc []byte
	dec trinary.Trytes
}{
	{[]byte{}, ""},
	{[]byte{0x94, 0x2c, 0xa2, 0x12, 0xea, 0xd1, 0xab, 0xa9, 0x00}, "9NOPQRSTUVWXYZ9"},
	{[]byte{0x1b, 0x06, 0x25, 0xb4, 0xc5, 0x54, 0x40, 0x76, 0x04}, "9ABCDEFGHIJKLM9"},
	{[]byte{0x0d}, "M"},                 // 2 trit padding
	{[]byte{0x79, 0x01}, "MM"},          // 4 trit padding
	{[]byte{0x79, 0x28}, "MMM"},         // 1 trit padding
	{[]byte{0x79, 0x79, 0x04}, "MMMM"},  // 3 trit padding
	{[]byte{0x79, 0x79, 0x79}, "MMMMM"}, // no padding
}

func TestEncode(t *testing.T) {
	for _, tt := range encDecTest {
		t.Run(tt.dec, func(t *testing.T) {
			dst := Encode(trinary.MustTrytesToTrits(tt.dec))
			assert.Equal(t, tt.enc, dst)
		})
	}
}

func TestEncodeTrytes(t *testing.T) {
	for _, tt := range encDecTest {
		t.Run(tt.dec, func(t *testing.T) {
			dst := EncodeTrytes(tt.dec)
			assert.Equal(t, tt.enc, dst)
		})
	}
}

func TestDecode(t *testing.T) {
	for _, tt := range encDecTest {
		t.Run(fmt.Sprintf("%x", tt.enc), func(t *testing.T) {
			dst, err := Decode(tt.enc)
			if assert.NoError(t, err) {
				// add expected padding
				paddedLen := ((len(tt.dec)*consts.TritsPerTryte + tritsPerByte - 1) / tritsPerByte) * tritsPerByte
				expDec := trinary.MustPadTrits(trinary.MustTrytesToTrits(tt.dec), paddedLen)
				assert.Equal(t, expDec, dst)
			}
		})
	}
}

func TestDecodeToTrytes(t *testing.T) {
	for _, tt := range encDecTest {
		t.Run(fmt.Sprintf("%x", tt.enc), func(t *testing.T) {
			dst, err := DecodeToTrytes(tt.enc)
			if assert.NoError(t, err) {
				// add expected padding
				padLend := (((len(tt.dec)*3+tritsPerByte-1)/tritsPerByte)*tritsPerByte)/3 - (len(tt.dec))
				expDec := trinary.MustPad(tt.dec, len(tt.dec)+padLend)
				assert.Equal(t, expDec, dst)
			}
		})
	}
}

func TestDecodeErr(t *testing.T) {
	var tests = []*struct {
		src []byte
		err error
	}{
		{[]byte{0x00, 0x7a}, consts.ErrInvalidByte},
		{[]byte{0x00, 0x80}, consts.ErrInvalidByte},
		{[]byte{0x00, 0x86}, consts.ErrInvalidByte},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("%x", tt.src), func(t *testing.T) {
			dst, err := Decode(tt.src)
			assert.Truef(t, errors.Is(err, tt.err), "unexpected error: %v", err)
			assert.Zero(t, dst)
		})
	}
}

func TestDecodeToTrytesErr(t *testing.T) {
	var tests = []*struct {
		src []byte
		err error
	}{
		{[]byte{0x0, 0x7a}, consts.ErrInvalidByte},
		{[]byte{0x0, 0x80}, consts.ErrInvalidByte},
		{[]byte{0x0, 0x86}, consts.ErrInvalidByte},
		{Encode([]int8{1, 1, 1, 0, 1}), ErrNonZeroPadding},
		{Encode([]int8{1, 1, 1, 0, -1}), ErrNonZeroPadding},
		{Encode([]int8{1, 1, 1, 1, 0}), ErrNonZeroPadding},
		{Encode([]int8{1, 1, 1, -1, 0}), ErrNonZeroPadding},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("%x", tt.src), func(t *testing.T) {
			dst, err := DecodeToTrytes(tt.src)
			assert.Truef(t, errors.Is(err, tt.err), "unexpected error: %v", err)
			assert.Zero(t, dst)
		})
	}
}

func BenchmarkEncode(b *testing.B) {
	data := make([]trinary.Trits, b.N)
	for i := range data {
		data[i] = randomTrits(5 * 200)
	}
	b.ResetTimer()

	for i := range data {
		_ = Encode(data[i])
	}
}

func BenchmarkDecode(b *testing.B) {
	data := make([][]byte, b.N)
	for i := range data {
		tmp := randomTrits(5 * 200)
		data[i] = Encode(tmp)
	}
	b.ResetTimer()

	for i := range data {
		_, _ = Decode(data[i])
	}
}

func randomTrits(n int) trinary.Trits {
	trytes := randomTrytes(n/3 + 1)
	return trinary.MustTrytesToTrits(trytes)[:n]
}

func randomTrytes(n int) trinary.Trytes {
	var result strings.Builder
	result.Grow(n)
	for i := 0; i < n; i++ {
		result.WriteByte(consts.TryteAlphabet[rand.Intn(len(consts.TryteAlphabet))])
	}
	return result.String()
}
