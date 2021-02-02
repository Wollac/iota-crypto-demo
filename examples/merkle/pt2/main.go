package main

import (
	"crypto"
	"encoding"
	"encoding/hex"
	"flag"
	"fmt"
	"math/bits"
	"math/rand"
	"strings"

	"github.com/wollac/iota-crypto-demo/pkg/merkle"

	_ "golang.org/x/crypto/blake2b" // BLAKE2b_256 is the default hashing algorithm
)

var (
	numHashes = flag.Int(
		"hashes",
		7,
		"number of random bundle hashes to be combined",
	)
)

type ID [32]byte

func (i ID) MarshalBinary() ([]byte, error) {
	return i[:], nil
}

func (i ID) String() string {
	return hex.EncodeToString(i[:])
}

func main() {
	flag.Parse()

	var data []encoding.BinaryMarshaler
	for i := 0; i < *numHashes; i++ {
		data = append(data, randomID())
	}

	fmt.Println("==> input message ids")
	for i := range data {
		fmt.Printf(" d[%d]: %s\n", i, data[i])
	}
	fmt.Printf("\n==> Merkle tree with %d leafs\n", len(data))
	printTree(merkle.NewHasher(crypto.BLAKE2b_256), data)
}

func randomID() (id ID) {
	rand.Read(id[:])
	return id
}

// printTree pretty prints the Merkle tree.
func printTree(h *merkle.Hasher, leafs []encoding.BinaryMarshaler) {
	root, _ := h.Hash(leafs)
	fmt.Printf(" root: %x\n", root)
	printNode(buildTree(h, leafs), "")
}

type node struct {
	text     string
	children []*node
}

func buildTree(h *merkle.Hasher, leafs []encoding.BinaryMarshaler) *node {
	if len(leafs) == 0 {
		return &node{text: fmt.Sprintf(" %x", h.EmptyRoot())}
	}
	if len(leafs) == 1 {
		leafHash, _ := h.Hash([]encoding.BinaryMarshaler{leafs[0]})
		return &node{text: fmt.Sprintf(" ┌ msg id: %s\n─┴ leaf: %x", leafs[0], leafHash)}
	}
	// largest power of two less than n, i.e. k < n <= 2k
	k := 1 << (bits.Len(uint(len(leafs)-1)) - 1)
	l, r := leafs[:k], leafs[k:]
	nodeHash, _ := h.Hash(leafs)
	return &node{
		text:     fmt.Sprintf(" node: %x", nodeHash),
		children: []*node{buildTree(h, l), buildTree(h, r)},
	}
}

func printNode(n *node, parentPrefix string) {
	var prefixes = [][]string{{" ├─", " │ "}, {" └─", "   "}}

	for i := range n.children {
		var p []string
		if i < len(n.children)-1 {
			p = prefixes[0]
		} else {
			p = prefixes[1]
		}
		lines := strings.Split(n.children[i].text, "\n")
		for j, line := range lines {
			if j < len(lines)-1 {
				fmt.Println(" " + parentPrefix + prefixes[0][1] + line)
			} else {
				fmt.Println(" " + parentPrefix + p[0] + line)
			}
		}
		printNode(n.children[i], parentPrefix+p[1])
	}
}
