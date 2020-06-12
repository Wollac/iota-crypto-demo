package main

import (
	"crypto/rand"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/iotaledger/iota.go/consts"
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
	language = flag.String(
		"language",
		"english",
		"language of the mnemonics",
	)
)

func main() {
	flag.Parse()

	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %s\n", err)
		os.Exit(1)
	}
}

func run() error {
	var err error

	if len(*seed) == 0 {
		*seed, err = generateSeed()
		if err != nil {
			return err
		}
	}
	if err := bip39.SetWordList(strings.ToLower(*language)); err != nil {
		return err
	}

	mnemonic, err := seedToMnemonic(*seed)
	if err != nil {
		return fmt.Errorf("failed encoding seed: %w", err)
	}
	decoded, err := mnemonicToSeed(mnemonic)
	if err != nil {
		return fmt.Errorf("failed decoding mnemonic: %w", err)
	}

	fmt.Println("==> IOTA Seed Mnemonics")

	fmt.Printf(" input seed (%d-tryte):\t\t%s\n", len(*seed), *seed)
	fmt.Printf(" mnemonic (%d-word):\t\t%s\n", len(mnemonic), mnemonic)
	fmt.Printf(" decoded seed (%d-tryte):\t%s\n", len(decoded), decoded)

	return nil
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

func generateSeed() (trinary.Hash, error) {
	entropy := make([]byte, consts.HashBytesSize)
	if _, err := rand.Read(entropy); err != nil {
		return "", fmt.Errorf("error generating entropy: %s", err)
	}
	trytes, err := kerl.KerlBytesToTrytes(entropy)
	if err != nil {
		return "", fmt.Errorf("error converting seed: %s", err)
	}
	return trytes, nil
}

func validateSeed(seed trinary.Hash) error {
	if len(seed) != consts.HashTrytesSize {
		return consts.ErrInvalidTrytesLength
	}
	if err := trinary.ValidTrytes(seed); err != nil {
		return err
	}
	// a valid hash must have the last trit set to zero
	lastTrits := trinary.MustTrytesToTrits(string(seed[consts.HashTrytesSize-1]))
	if lastTrits[consts.TritsPerTryte-1] != 0 {
		return consts.ErrInvalidHash
	}
	return nil
}
