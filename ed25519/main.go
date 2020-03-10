package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/iotaledger/iota.go/consts"
	"github.com/iotaledger/iota.go/kerl"
	"github.com/iotaledger/iota.go/transaction"
	"github.com/iotaledger/iota.go/trinary"
	"github.com/wollac/iota-bip39-demo/pkg/ed25519/address"
	"github.com/wollac/iota-bip39-demo/pkg/ed25519/bundle"
)

var (
	numInputs = flag.Int(
		"inputs",
		1,
		"number of ed25519 inputs in the generated bundle",
	)
	timestamp = flag.Uint64(
		"timestamp",
		uint64(time.Now().Unix()),
		"bundle timestamp, in Unix time (seconds)",
	)
)

var output = bundle.Transfer{
	Address: consts.NullHashTrytes,
	Value:   1000000000,
	Tag:     "EDTWOFIVEFIVEONENINE",
}

func main() {
	flag.Parse()

	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %s\n", err)
		os.Exit(1)
	}
}

func run() error {
	fmt.Println("==> Bundle Parameters")
	fmt.Printf(" Output\n")
	fmt.Printf("  address (%d-tryte):\t%s\n", len(output.Address), output.Address)
	fmt.Printf("  tag (%d-tryte):\t%s\n", consts.TagTrinarySize/3, strings.TrimRight(output.Tag, "9"))
	fmt.Printf("  bundle timestamp:\t%v\n", time.Unix(int64(*timestamp), 0))

	var inputs []bundle.Input
	for i := 0; i < *numInputs; i++ {
		seed, err := generateEntropy(ed25519.SeedSize)
		if err != nil {
			return err
		}
		keyPair := ed25519.NewKeyFromSeed(seed)
		addressTrytes, err := address.Generate(keyPair)
		if err != nil {
			return err
		}

		input := bundle.Input{
			KeyPair: keyPair,
			Value:   output.Value / uint64(*numInputs),
		}
		if i == 0 {
			input.Value += output.Value % uint64(*numInputs) // add the remaining value
		}
		inputs = append(inputs, input)

		fmt.Printf(" Input #%d:\n", i+1)
		if err := printInput(keyPair, addressTrytes, "  "); err != nil {
			return err
		}
	}

	bndl, err := bundle.Generate(bundle.Transfers{output}, inputs, *timestamp)
	if err != nil {
		return err
	}
	// do a sanity check of signatures and structure
	if err := bundle.Validate(bndl); err != nil {
		return err
	}

	fmt.Printf("\n==> Signed Bundle\n")
	if err := printBundle(bndl); err != nil {
		return err
	}
	return nil
}

func generateEntropy(size int) ([]byte, error) {
	entropy := make([]byte, size)
	if _, err := rand.Read(entropy); err != nil {
		return nil, err
	}
	return entropy, nil
}

func printInput(keyPair ed25519.PrivateKey, addressTrytes trinary.Trytes, indent string) error {
	privateKey := keyPair.Seed()
	publicKey := keyPair.Public().(ed25519.PublicKey)
	addressBytes, err := kerl.KerlTrytesToBytes(addressTrytes)
	if err != nil {
		return err
	}

	fmt.Printf("%sprivate key (%d-byte):%x\n", indent, len(privateKey), privateKey)
	fmt.Printf("%spublic key (%d-byte):\t%x\n", indent, len(publicKey), publicKey)
	fmt.Printf("%spubkey hash (%d-byte):%x\n", indent, len(addressBytes), addressBytes)
	fmt.Printf("%saddress (%d-tryte):\t%s\n", indent, len(addressTrytes), addressTrytes)
	return nil
}

func printBundle(txs []transaction.Transaction) error {
	var shortened []transaction.Transaction
	for i := range txs {
		tx := transaction.Transaction{
			SignatureMessageFragment: strings.TrimRight(txs[i].SignatureMessageFragment, "9"),
			Address:                  txs[i].Address,
			Value:                    txs[i].Value,
			ObsoleteTag:              strings.TrimRight(txs[i].ObsoleteTag, "9"),
			Timestamp:                txs[i].Timestamp,
			CurrentIndex:             txs[i].CurrentIndex,
			LastIndex:                txs[i].LastIndex,
			Bundle:                   txs[i].Bundle,
			Tag:                      strings.TrimRight(txs[i].Tag, "9"),
		}
		shortened = append(shortened, tx)
	}
	// pretty marshal
	b, err := json.MarshalIndent(shortened, "", " ")
	if err != nil {
		return err
	}
	fmt.Printf("%s\n", b)
	return nil
}
