package b1t6

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/iotaledger/iota.go/trinary"
	"github.com/stretchr/testify/assert"
)

var encDecTests = []*struct {
	bytes  []byte
	trytes trinary.Trytes
}{
	{[]byte{}, ""},
	{[]byte{1}, "A9"},
	{[]byte{127}, "SE"},
	{[]byte{128}, "GV"},
	{[]byte{255}, "Z9"},
	{[]byte{0, 1}, "99A9"}, // endianness
	{bytes.Repeat([]byte{0, 1}, 25), strings.Repeat("99A9", 25)}, // long
	// RFC examples
	{decodeHex("00"), "99"},
	{decodeHex("0001027e7f8081fdfeff"), "99A9B9RESEGVHVX9Y9Z9"},
	{decodeHex("9ba06c78552776a596dfe360cc2b5bf644c0f9d343a10e2e71debecd30730d03"), "GWLW9DLDDCLAJDQXBWUZYZODBYPBJCQ9NCQYT9IYMBMWNASBEDTZOYCYUBGDM9C9"},
}

func TestEncode(t *testing.T) {
	for _, tt := range encDecTests {
		t.Run(fmt.Sprintf("%x", tt.bytes), func(t *testing.T) {
			dst := Encode(tt.bytes)
			assert.Equal(t, trinary.MustTrytesToTrits(tt.trytes), dst)
		})
	}
}

func TestEncodeToTrytes(t *testing.T) {
	for _, tt := range encDecTests {
		t.Run(fmt.Sprintf("%x", tt.bytes), func(t *testing.T) {
			dst := EncodeToTrytes(tt.bytes)
			assert.Equal(t, tt.trytes, dst)
		})
	}
}

func TestDecode(t *testing.T) {
	for _, tt := range encDecTests {
		t.Run(tt.trytes, func(t *testing.T) {
			dst, err := Decode(trinary.MustTrytesToTrits(tt.trytes))
			if assert.NoError(t, err) {
				assert.Equal(t, tt.bytes, dst)
			}
		})
	}
}

func TestDecodeTrytes(t *testing.T) {
	for _, tt := range encDecTests {
		t.Run(tt.trytes, func(t *testing.T) {
			dst, err := DecodeTrytes(tt.trytes)
			if assert.NoError(t, err) {
				assert.Equal(t, tt.bytes, dst)
			}
		})
	}
}

func TestDecodeErr(t *testing.T) {
	var tests = []*struct {
		src trinary.Trits
		err error
	}{
		{trinary.Trits{0, 0, 0, 0, 0}, ErrInvalidLength},
		{trinary.Trits{1, 0, 0}, ErrInvalidLength},
		{trinary.Trits{-1, 1, -1, -1, -1, 1}, ErrInvalidTrits},
		{trinary.Trits{0, -1, 1, 1, 1, -1}, ErrInvalidTrits},
		{trinary.Trits{1, 1, 1, 1, 1, 1}, ErrInvalidTrits},
		{trinary.Trits{-1, -1, -1, -1, -1, -1}, ErrInvalidTrits},
		{trinary.Trits{0, 1, 1, 0, 0, 1}, ErrInvalidTrits},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprint(tt.src), func(t *testing.T) {
			dst, err := Decode(tt.src)
			assert.Truef(t, errors.Is(err, tt.err), "unexpected error: %v", err)
			assert.Zero(t, dst)
		})
	}
}

func TestDecodeToTrytesErr(t *testing.T) {
	var tests = []*struct {
		src trinary.Trytes
		err error
	}{
		{"A", ErrInvalidLength},
		{"TE", ErrInvalidTrits},
		{"FV", ErrInvalidTrits},
		{"MM", ErrInvalidTrits},
		{"NN", ErrInvalidTrits},
		{"LI", ErrInvalidTrits},
	}

	for _, tt := range tests {
		t.Run(tt.src, func(t *testing.T) {
			dst, err := DecodeTrytes(tt.src)
			assert.Truef(t, errors.Is(err, tt.err), "unexpected error: %v", err)
			assert.Zero(t, dst)
		})
	}
}

func BenchmarkEncode(b *testing.B) {
	data := make([][]byte, b.N)
	for i := range data {
		data[i] = make([]byte, 200)
		if _, err := rand.Read(data[i]); err != nil {
			b.Fatal(err)
		}
	}
	b.ResetTimer()

	for i := range data {
		_ = EncodeToTrytes(data[i])
	}
}

func BenchmarkDecode(b *testing.B) {
	data := make([]trinary.Trytes, b.N)
	for i := range data {
		tmp := make([]byte, 200)
		if _, err := rand.Read(tmp); err != nil {
			b.Fatal(err)
		}
		data[i] = EncodeToTrytes(tmp)
	}
	b.ResetTimer()

	for i := range data {
		_, _ = DecodeTrytes(data[i])
	}
}

func decodeHex(s string) []byte {
	dst, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return dst
}
