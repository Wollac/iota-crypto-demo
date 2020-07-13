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

var testBytes = []*struct {
	bytes     []byte
	expTrytes trinary.Trytes
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

func TestEncodeToTrytes(t *testing.T) {
	for _, tt := range testBytes {
		t.Run(fmt.Sprintf("%x", tt.bytes), func(t *testing.T) {
			trytes := EncodeToTrytes(tt.bytes)
			assert.Equal(t, tt.expTrytes, trytes)
		})
	}
}

var testTrytes = []*struct {
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

func TestDecodeTrytes(t *testing.T) {
	for _, tt := range testTrytes {
		t.Run(tt.trytes, func(t *testing.T) {
			bs, err := DecodeTrytes(tt.trytes)
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
