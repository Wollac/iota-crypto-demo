package main

import (
	"flag"
	"fmt"
	"math/bits"
	"math/rand"
	"strings"

	merkle "github.com/wollac/iota-crypto-demo/pkg/merkle/pt2"
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

	var ids [][32]byte
	for i := 0; i < *numHashes; i++ {
		ids = append(ids, randomID())
	}

	fmt.Println("==> input message ids")
	for i := range ids {
		fmt.Printf(" d[%d]: %x\n", i, ids[i])
	}
	fmt.Printf("\n==> Merkle tree with %d leafs\n", len(ids))
	printTree(merkle.DefaultHasher, ids)
}

func randomID() (p [32]byte) {
	rand.Read(p[:])
	return p
}

// printTree pretty prints the Merkle tree.
func printTree(h *merkle.Hasher, ids [][32]byte) {
	root := h.TreeHash(ids)
	fmt.Printf(" root: %x\n", root)
	printNode(buildTree(h, ids), "")
}

type node struct {
	text     string
	children []*node
}

func buildTree(h *merkle.Hasher, ids [][32]byte) *node {
	if len(ids) == 0 {
		return &node{text: fmt.Sprintf(" %x", h.EmptyRoot())}
	}
	if len(ids) == 1 {
		return &node{text: fmt.Sprintf(" ┌ msg id: %x\n─┴ leaf: %x", ids[0], h.HashLeaf(ids[0]))}
	}
	// largest power of two less than n, i.e. k < n <= 2k
	k := 1 << (bits.Len(uint(len(ids)-1)) - 1)
	l, r := ids[:k], ids[k:]
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
