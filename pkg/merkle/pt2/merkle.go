/*
Package merkle implements the Merkle tree hash computation of a list of message IDs.
*/
package merkle

import (
	"crypto"
	"math/bits"

	_ "golang.org/x/crypto/blake2b" // BLAKE2b_256 is the default hashing algorithm
)

// DefaultHasher is a BLAKE2 based Merkle tree.
var DefaultHasher = New(crypto.BLAKE2b_256)

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
func (t *Hasher) TreeHash(ids [][32]byte) []byte {
	if len(ids) == 0 {
		return t.EmptyRoot()
	}
	if len(ids) == 1 {
		return t.HashLeaf(ids[0])
	}

	k := largestPowerOfTwo(len(ids))
	return t.HashNode(t.TreeHash(ids[:k]), t.TreeHash(ids[k:]))
}

// HashLeaf returns the Merkle tree leaf hash of the provided ternary hash.
func (t *Hasher) HashLeaf(id [32]byte) []byte {
	h := t.New()
	h.Write([]byte{LeafHashPrefix})
	h.Write(id[:])
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
