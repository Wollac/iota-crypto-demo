package b1t6

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/iotaledger/iota.go/consts"
	"github.com/iotaledger/iota.go/trinary"
	"github.com/stretchr/testify/assert"
)

func TestEncode(t *testing.T) {
	var test = []*struct {
		bytes     []byte
		expTrytes trinary.Trytes
		expErr    error
	}{
		{[]byte{}, "", nil},
		{[]byte{1}, "A9", nil},
		{[]byte{127}, "SE", nil},
		{[]byte{128}, "GV", nil},
		{[]byte{255}, "Z9", nil},
		{[]byte{0, 1}, "99A9", nil}, // endianness
		{bytes.Repeat([]byte{0, 1}, 25), strings.Repeat("99A9", 25), nil}, // long
		// RFC examples
		{decodeHex("00"), "99", nil},
		{decodeHex("0001027e7f8081fdfeff"), "99A9B9RESEGVHVX9Y9Z9", nil},
		{decodeHex("9ba06c78552776a596dfe360cc2b5bf644c0f9d343a10e2e71debecd30730d03"), "GWLW9DLDDCLAJDQXBWUZYZODBYPBJCQ9NCQYT9IYMBMWNASBEDTZOYCYUBGDM9C9", nil},
	}

	for _, tt := range test {
		t.Run(fmt.Sprintf("%x", tt.bytes), func(t *testing.T) {
			if tt.expErr == nil {
				trytes := Encode(tt.bytes)
				assert.Equal(t, tt.expTrytes, trytes)
			}
		})
	}
}

func TestDecode(t *testing.T) {
	var tests = []*struct {
		trytes   trinary.Trytes
		expBytes []byte
		expErr   error
	}{
		{"", []byte{}, nil},                       // empty
		{"A", nil, consts.ErrInvalidTrytesLength}, // odd
		{"TE", nil, consts.ErrInvalidTrytes},      // not a byte
		{"FV", nil, consts.ErrInvalidTrytes},      // not a byte
		{"MM", nil, consts.ErrInvalidTrytes},      // not a byte
		{"NN", nil, consts.ErrInvalidTrytes},      // not a byte
		{"LI", nil, consts.ErrInvalidTrytes},      // not a byte
		{"22", nil, consts.ErrInvalidTrytes},      // not a tryte
		{"A9", []byte{1}, nil},
		{"SE", []byte{127}, nil},
		{"GV", []byte{128}, nil},
		{"Z9", []byte{255}, nil},
		{"99A9", []byte{0, 1}, nil},                                       // endianness
		{strings.Repeat("99A9", 25), bytes.Repeat([]byte{0, 1}, 25), nil}, // long
		// RFC examples
		{"99", decodeHex("00"), nil},
		{"99A9B9RESEGVHVX9Y9Z9", decodeHex("0001027e7f8081fdfeff"), nil},
		{"GWLW9DLDDCLAJDQXBWUZYZODBYPBJCQ9NCQYT9IYMBMWNASBEDTZOYCYUBGDM9C9", decodeHex("9ba06c78552776a596dfe360cc2b5bf644c0f9d343a10e2e71debecd30730d03"), nil},
	}

	for _, tt := range tests {
		t.Run(tt.trytes, func(t *testing.T) {
			bs, err := Decode(tt.trytes)
			if assert.Truef(t, errors.Is(err, tt.expErr), "unexpected error: %v", err) {
				assert.Equal(t, tt.expBytes, bs)
			}
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
		_ = Encode(data[i])
	}
}

func BenchmarkDecode(b *testing.B) {
	data := make([]trinary.Trytes, b.N)
	for i := range data {
		tmp := make([]byte, 200)
		if _, err := rand.Read(tmp); err != nil {
			b.Fatal(err)
		}
		data[i] = Encode(tmp)
	}
	b.ResetTimer()

	for i := range data {
		_, _ = Decode(data[i])
	}
}

func decodeHex(s string) []byte {
	dst, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return dst
}
