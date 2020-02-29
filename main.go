package main

import (
	"fmt"
	"log"

	flag "github.com/spf13/pflag"
	"github.com/wollac/iota-bip39-demo/bip32path"
	"github.com/wollac/iota-bip39-demo/slip10"
)

var (
	seed       = flag.BytesHex("seed", []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}, "bytes of the master seed (hex)")
	pathString = flag.String("path", "44'/4218'/0'/0'", "string form of the BIP-32 path to derive the extended private key")
)

func main() {
	flag.Parse()

	path, err := bip32path.ParsePath(*pathString)
	if err != nil {
		log.Fatalf("invalid path (%s): %s", *pathString, err)
	}

	curve := slip10.Ed25519()
	key, _ := slip10.DeriveKeyFromPath(*seed, curve, path)

	fmt.Printf("chain code: %x\n", key.ChainCode)
	fmt.Printf("private: %x\n", key.Key)
	fmt.Printf("public: %x\n", curve.PublicKey(key))
}
