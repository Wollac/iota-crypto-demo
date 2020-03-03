package main

import (
	"fmt"
	"log"

	"github.com/iotaledger/iota.go/consts"
	"github.com/iotaledger/iota.go/kerl"
	"github.com/iotaledger/iota.go/trinary"
	flag "github.com/spf13/pflag"
	"github.com/wollac/iota-bip39-demo/pkg/bip32path"
	"github.com/wollac/iota-bip39-demo/pkg/bip39"
	"github.com/wollac/iota-bip39-demo/pkg/slip10"
)

var (
	mnemonicString = flag.String("mnemonic", "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about", "BIP-39 mnemonic sentence")
	passphrase     = flag.String("passphrase", "", "optional passphrase")
	pathString     = flag.String("path", "44'/4218'/0'/0'", "string form of the BIP-32 path to derive the extended private key")
)

func main() {
	flag.Parse()

	mnemonic := bip39.ParseMnemonic(*mnemonicString)
	seed := bip39.MnemonicToSeed(mnemonic, *passphrase)

	path, err := bip32path.ParsePath(*pathString)
	if err != nil {
		log.Fatalf("invalid path (%s): %s", *pathString, err)
	}

	kerl.NewKerl()
	curve := slip10.Ed25519()
	key, _ := slip10.DeriveKeyFromPath(seed, curve, path)

	fmt.Printf("master seed: %x\n", seed)
	fmt.Printf("chain code: %x\n", key.ChainCode)
	fmt.Printf("private: %x\n", key.Key)
	fmt.Printf("public: %x\n", curve.PublicKey(key))
	fmt.Printf("IOTA seed: %s\n", iotaSeedFromKey(key))
}

func iotaSeedFromKey(key *slip10.Key) trinary.Hash {
	var entropy []byte
	entropy = append(entropy, key.Key...)
	entropy = append(entropy, key.ChainCode...)

	hash := kerl.NewKerl()
	in, err := kerl.KerlBytesToTrytes(entropy[:consts.HashBytesSize])
	if err != nil {
		panic(err)
	}
	hash.MustAbsorbTrytes(in)
	in, err = kerl.KerlBytesToTrytes(entropy[len(entropy)-consts.HashBytesSize:])
	if err != nil {
		panic(err)
	}
	hash.MustAbsorbTrytes(in)

	return hash.MustSqueezeTrytes(consts.HashTrinarySize)
}
