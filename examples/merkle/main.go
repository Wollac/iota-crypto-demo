package main

import (
	"flag"
	"fmt"
	"math/bits"
	"math/rand"
	"strings"

	"github.com/iotaledger/iota.go/consts"
	"github.com/iotaledger/iota.go/trinary"
	"github.com/wollac/iota-bip39-demo/internal/byteconv"
	"github.com/wollac/iota-bip39-demo/pkg/merkle"
)

var (
	numHashes = flag.Int(
		"hashes",
		7,
		"number of random bundle hashes to be combined",
	)
)

func main() {
	flag.Parse()

	var hashes []trinary.Hash
	for i := 0; i < *numHashes; i++ {
		hashes = append(hashes, randomTrytes(consts.HashTrytesSize))
	}

	fmt.Println("==> input tx hashes")
	for i := range hashes {
		fmt.Printf(" d[%d]: %s\n", i, hashes[i])
	}
	fmt.Printf("\n==> Merkle tree with %d leafs\n", len(hashes))
	printTree(merkle.DefaultHasher, hashes)
}

func randomTrytes(n int) trinary.Hash {
	var trytes strings.Builder
	trytes.Grow(n)
	for i := 0; i < n; i++ {
		trytes.WriteByte(consts.TryteAlphabet[rand.Intn(len(consts.TryteAlphabet))])
	}
	return trytes.String()
}

// printTree pretty prints the Merkle tree.
func printTree(h *merkle.Hasher, hashes []trinary.Hash) {
	root := h.TreeHash(hashes)
	fmt.Printf(" Htri: %s\n root: %x\n", byteconv.MustBytesToTrytes(root), root)
	printNode(buildTree(h, hashes), "")

}

type node struct {
	text     string
	children []*node
}

func buildTree(h *merkle.Hasher, hashes []trinary.Hash) *node {
	if len(hashes) == 0 {
		return &node{text: fmt.Sprintf(" %x", h.EmptyRoot())}
	}
	if len(hashes) == 1 {
		return &node{text: fmt.Sprintf(" ┌ tx hash: %s\n─┴ leaf: %x", hashes[0], h.HashLeaf(hashes[0]))}
	}
	// largest power of two less than n, i.e. k < n <= 2k
	k := 1 << (bits.Len(uint(len(hashes)-1)) - 1)
	l, r := hashes[:k], hashes[k:]
	return &node{
		text:     fmt.Sprintf(" node: %x", h.HashNode(h.TreeHash(l), h.TreeHash(r))),
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
