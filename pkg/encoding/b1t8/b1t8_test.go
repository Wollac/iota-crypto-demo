package b1t8

import (
	"errors"
	"fmt"
	"math/rand"
	"testing"

	"github.com/iotaledger/iota.go/trinary"
	"github.com/stretchr/testify/assert"
)

var encDecTests = []*struct {
	bytes []byte
	trits trinary.Trits
}{
	{[]byte{}, []int8{}},
	{[]byte{0x00}, []int8{0, 0, 0, 0, 0, 0, 0, 0}},
	{[]byte{0x01}, []int8{1, 0, 0, 0, 0, 0, 0, 0}},
	{[]byte{0x80}, []int8{0, 0, 0, 0, 0, 0, 0, 1}},
	{[]byte{0xaa}, []int8{0, 1, 0, 1, 0, 1, 0, 1}},
	{[]byte{0x55}, []int8{1, 0, 1, 0, 1, 0, 1, 0}},
	{[]byte{0xff}, []int8{1, 1, 1, 1, 1, 1, 1, 1}},
	{[]byte{0x00, 0x01}, []int8{0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0}}, // endianness
}

func TestEncode(t *testing.T) {
	for _, tt := range encDecTests {
		t.Run(fmt.Sprintf("%x", tt.bytes), func(t *testing.T) {
			dst := make(trinary.Trits, EncodedLen(len(tt.bytes)))
			n := Encode(dst, tt.bytes)
			assert.Equal(t, EncodedLen(len(tt.bytes)), n)
			assert.Equal(t, tt.trits, dst)
		})
	}
}

func TestDecode(t *testing.T) {
	for _, tt := range encDecTests {
		t.Run(fmt.Sprint(tt.trits), func(t *testing.T) {
			dst := make([]byte, DecodedLen(len(tt.trits)))
			n, err := Decode(dst, tt.trits)
			if assert.NoError(t, err) {
				assert.Equal(t, DecodedLen(len(tt.trits)), n)
				assert.Equal(t, tt.bytes, dst)
			}
		})
	}
}

func TestDecodeErr(t *testing.T) {
	var tests = []*struct {
		src trinary.Trits
		dst []byte
		err error
	}{
		{trinary.Trits{0, 0, 0, 0, 0, 0, 0}, []byte{}, ErrInvalidLength},
		{trinary.Trits{1, 0, 0}, []byte{}, ErrInvalidLength},
		{trinary.Trits{1, 0, 0, 0, 0, 0, 0, 0, 0}, []byte{1}, ErrInvalidLength},
		{trinary.Trits{-1, 0, 0, 0, 0, 0, 0, 0}, []byte{}, ErrInvalidTrit},
		{trinary.Trits{-1, 0, 0, 0, 0, 0, 0, 0}, []byte{}, ErrInvalidTrit},
		{trinary.Trits{1, 1, 1, 1, 1, 1, 1, 1, -1}, []byte{0xff}, ErrInvalidTrit},
		{trinary.Trits{0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, -1}, []byte{0, 1}, ErrInvalidTrit},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprint(tt.src), func(t *testing.T) {
			dst := make([]byte, DecodedLen(len(tt.src)))
			n, err := Decode(dst, tt.src)
			assert.Truef(t, errors.Is(err, tt.err), "unexpected error: %v", err)
			assert.Equal(t, tt.dst, dst[:n])
		})
	}
}

var (
	benchBytesLen = 1000
	benchTritsLen = EncodedLen(benchBytesLen)
)

func BenchmarkEncode(b *testing.B) {
	data := make([][]byte, b.N)
	for i := range data {
		data[i] = randomBytes(benchBytesLen)
	}
	b.ResetTimer()

	dst := make(trinary.Trits, benchTritsLen)
	for i := range data {
		_ = Encode(dst, data[i])
	}
}

func BenchmarkDecode(b *testing.B) {
	data := make([]trinary.Trits, b.N)
	for i := range data {
		data[i] = make(trinary.Trits, benchTritsLen)
		Encode(data[i], randomBytes(benchBytesLen))
	}
	b.ResetTimer()

	dst := make([]byte, benchBytesLen)
	for i := range data {
		_, _ = Decode(dst, data[i])
	}
}

func randomBytes(n int) []byte {
	result := make([]byte, n)
	rand.Read(result)
	return result
}
