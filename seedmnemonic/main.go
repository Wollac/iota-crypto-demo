package main

import (
	"crypto/rand"
	"errors"
	"flag"
	"fmt"
	"log"

	"github.com/iotaledger/iota.go/consts"
	"github.com/iotaledger/iota.go/guards"
	"github.com/iotaledger/iota.go/kerl"
	"github.com/iotaledger/iota.go/trinary"
	"github.com/wollac/iota-bip39-demo/pkg/bip39"
)

var (
	seed = flag.String(
		"seed",
		"",
		"IOTA seed; if empty a new random seed is generated",
	)
)

func main() {
	flag.Parse()

	if len(*seed) == 0 {
		*seed = generateSeed()
	}

	mnemonic, err := seedToMnemonic(*seed)
	if err != nil {
		log.Fatalf("error encoding mnemonic: %s", err)
	}
	decoded, err := mnemonicToSeed(mnemonic)
	if err != nil {
		log.Fatalf("error decoding seed: %s", err)
	}

	fmt.Println("==> IOTA Seed Mnemonics")

	fmt.Printf("input seed(%d-tryte):\t%s\n", len(*seed), *seed)
	fmt.Printf("mnemonic(%d-word):\t%s\n", len(mnemonic), mnemonic)
	fmt.Printf("decoded seed(%d-tryte):\t%s\n", len(decoded), decoded)
}

func seedToMnemonic(seed trinary.Hash) (bip39.Mnemonic, error) {
	err := validateSeed(seed)
	if err != nil {
		return nil, err
	}
	seedBytes, err := kerl.KerlTrytesToBytes(seed)
	if err != nil {
		return nil, err
	}
	mnemonic, err := bip39.EntropyToMnemonic(seedBytes)
	if err != nil {
		return nil, err
	}
	return mnemonic, nil
}

func mnemonicToSeed(mnemonic bip39.Mnemonic) (trinary.Hash, error) {
	seedBytes, err := bip39.MnemonicToEntropy(mnemonic)
	if err != nil {
		return "", err
	}
	return kerl.KerlBytesToTrytes(seedBytes)
}
func generateSeed() trinary.Hash {
	entropy := make([]byte, consts.HashBytesSize)
	if _, err := rand.Read(entropy); err != nil {
		log.Fatalf("error generating entropy: %s", err)
	}
	trytes, err := kerl.KerlBytesToTrytes(entropy)
	if err != nil {
		log.Fatalf("error converting seed: %s", err)
	}
	return trytes
}

func validateSeed(seed trinary.Hash) error {
	if !guards.IsTrytesOfExactLength(seed, consts.HashTrytesSize) {
		return errors.New("invalid trytes")
	}
	// last bundle seed trit must be zero
	lastTrits := trinary.MustTrytesToTrits(string(seed[consts.HashTrytesSize-1]))
	if lastTrits[consts.TritsPerTryte-1] != 0 {
		return errors.New("last trit not zero")
	}
	return nil
}
