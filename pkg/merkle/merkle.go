/*
Package merkle implements the Merkle tree hash computation of a list of bundle hashes.
*/
package merkle

import (
	"crypto"
	"math/bits"

	"github.com/iotaledger/iota.go/trinary"
	_ "golang.org/x/crypto/blake2b" // BLAKE2b_512 is the default hashing algorithm
)

// DefaultHasher is a BLAKE2 based Merkle tree.
var DefaultHasher = New(crypto.BLAKE2b_512)

// Domain separation prefixes
const (
	LeafHashPrefix = 0
	NodeHashPrefix = 1
)

// Hasher implements the RFC6962 tree hashing algorithm.
type Hasher struct {
	crypto.Hash
}

// New creates a new Hashers based on the passed in hash function.
func New(h crypto.Hash) *Hasher {
	return &Hasher{Hash: h}
}

// EmptyRoot returns a special case for an empty tree.
func (t *Hasher) EmptyRoot() []byte {
	return t.New().Sum(nil)
}

// TreeHash computes the Merkle tree hash of the provided ternary hashes.
func (t *Hasher) TreeHash(hashes []trinary.Hash) []byte {
	if len(hashes) == 0 {
		return t.EmptyRoot()
	}
	if len(hashes) == 1 {
		return t.HashLeaf(hashes[0])
	}

	k := largestPowerOfTwo(len(hashes))
	return t.HashNode(t.TreeHash(hashes[:k]), t.TreeHash(hashes[k:]))
}

// HashLeaf returns the Merkle tree leaf hash of the provided ternary hash.
func (t *Hasher) HashLeaf(hash trinary.Hash) []byte {
	h := t.New()
	h.Write([]byte{LeafHashPrefix})
	h.Write(trinary.MustTrytesToBytes(hash))
	return h.Sum(nil)
}

// HashNode returns the inner Merkle tree node hash of the two child nodes l and r.
func (t *Hasher) HashNode(l, r []byte) []byte {
	h := t.New()
	h.Write([]byte{NodeHashPrefix})
	h.Write(l)
	h.Write(r)
	return h.Sum(nil)
}

// largestPowerOfTwo returns the largest power of two less than n.
func largestPowerOfTwo(x int) int {
	if x < 2 {
		panic("invalid value")
	}
	return 1 << (bits.Len(uint(x-1)) - 1)
}
