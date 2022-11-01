package v2

import (
	"encoding/binary"
	"math"
	"math/big"

	"golang.org/x/crypto/blake2b"

	"github.com/iotaledger/iota.go/consts"
	"github.com/iotaledger/iota.go/curl"
	"github.com/iotaledger/iota.go/encoding/b1t6"
	"github.com/iotaledger/iota.go/trinary"

	_ "golang.org/x/crypto/blake2b" // BLAKE2b_256 is the default hash function for the PoW digest
)

const (
	nonceBytes     = 8  // len(uint64)
	tritsPerUint64 = 40 // largest x s.t. 3^x <= maxUint64
)

var (
	// largest possible integer representation of a Curl hash, i.e. 3^243
	maxHash = hexToInt("2367b879df2fe073dfc27f021fbc70343b4661546d9dcaa0de38db00a48d9b295613405167b19e1ddba02c679e2d7385b")
	// largest power of 3 fitting in an uint64, i.e. 3^tritsPerUint64 = 3^40
	uint64Radix = new(big.Int).SetUint64(12157665459056928801)
	one         = new(big.Int).SetUint64(1)
)

func hexToInt(s string) *big.Int {
	b, _ := new(big.Int).SetString(s, 16)
	return b
}

// Score returns the PoW score of msg.
func Score(msg []byte) uint64 {
	if len(msg) < nonceBytes {
		panic("pow: invalid message length")
	}

	dataLen := len(msg) - nonceBytes
	// the PoW digest is the hash of msg without the nonce
	powDigest := blake2b.Sum256(msg[:dataLen])

	// extract the nonce from msg and compute the number of trailing zeros
	nonce := binary.LittleEndian.Uint64(msg[dataLen:])
	d := difficulty(powDigest[:], nonce)

	// the score is the difficulty per bytes, so we need to divide by the message length
	if d.IsUint64() {
		return d.Uint64() / uint64(len(msg))
	}
	// try big.Int division
	d.Quo(d, big.NewInt(int64(len(msg))))
	if d.IsUint64() {
		return d.Uint64()
	}
	// otherwise return the largest possible score
	return math.MaxUint64
}

func difficulty(powDigest []byte, nonce uint64) *big.Int {
	// allocate exactly one Curl block
	buf := make(trinary.Trits, consts.HashTrinarySize)
	n := b1t6.Encode(buf, powDigest)
	// add the nonce to the trit buffer
	encodeNonce(buf[n:], nonce)

	c := curl.NewCurlP81()
	if err := c.Absorb(buf); err != nil {
		panic(err)
	}
	digest, _ := c.Squeeze(consts.HashTrinarySize)

	h := toInt(digest)
	return h.Quo(maxHash, h)
}

// encodeNonce encodes nonce as 48 trits using the b1t6 encoding.
func encodeNonce(dst trinary.Trits, nonce uint64) {
	var nonceBuf [nonceBytes]byte
	binary.LittleEndian.PutUint64(nonceBuf[:], nonce)
	b1t6.Encode(dst, nonceBuf[:])
}

// toInt converts the little-endian trinary hash into a positive integer.
// It returns t[242]*3^242 + ... + t[0]*3^0 + 1, where t[i] = { 2 if trits[i] = -1, trits[i] otherwise }.
func toInt(trits trinary.Trits) *big.Int {
	if len(trits) != consts.HashTrinarySize {
		panic("pow: invalid hash")
	}

	const n = consts.HashTrinarySize
	b := new(big.Int).SetUint64(tritToUint(trits[n-1])*9 + tritToUint(trits[n-2])*3 + tritToUint(trits[n-3]))

	// process as uint64 chunks to avoid costly bigint multiplication
	tmp := new(big.Int)
	for i := consts.HashTrinarySize/tritsPerUint64 - 1; i >= 0; i-- {
		chunk := trits[i*tritsPerUint64 : i*tritsPerUint64+tritsPerUint64]

		var v uint64
		for j := len(chunk) - 1; j >= 0; j-- {
			v = v*3 + tritToUint(chunk[j])
		}
		if i == 0 {
			v++
		}
		b.Add(b.Mul(b, uint64Radix), tmp.SetUint64(v))
	}
	return b
}

func tritToUint(t int8) uint64 {
	if t == -1 {
		return 2
	}
	return uint64(t)
}
