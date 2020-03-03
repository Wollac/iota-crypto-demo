package main

import (
	"crypto/rand"
	"flag"
	"fmt"
	"log"

	"github.com/iotaledger/iota.go/consts"
	"github.com/iotaledger/iota.go/kerl"
	"github.com/iotaledger/iota.go/trinary"
	"github.com/wollac/iota-bip39-demo/pkg/bip32path"
	"github.com/wollac/iota-bip39-demo/pkg/bip39"
	"github.com/wollac/iota-bip39-demo/pkg/slip10"
)

var (
	mnemonicString = flag.String(
		"mnemonic",
		"abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
		"mnemonic sentence according to BIP-39, 12-48 words are supported; if empty a random entropy is generated",
	)
	passphrase = flag.String(
		"passphrase",
		"",
		"secret passphrase to generate the master seed; can be empty",
	)
	pathString = flag.String(
		"path",
		"44'/4218'/0'/0'",
		"string form of the BIP-32 address path to derive the extended private key",
	)
)

func main() {
	var (
		err      error
		entropy  []byte
		mnemonic bip39.Mnemonic
	)
	flag.Parse()

	if len(*mnemonicString) == 0 {
		// no mnemonic given, generate
		entropy = generateEntropy(256 / 8 /* 256 bits */)
		mnemonic, _ = bip39.EntropyToMnemonic(entropy)
	} else {
		mnemonic = bip39.ParseMnemonic(*mnemonicString)
		entropy, err = bip39.MnemonicToEntropy(mnemonic)
		if err != nil {
			log.Fatalf("invalid mnemonic: %s", err)
		}
	}

	seed, _ := bip39.MnemonicToSeed(mnemonic, *passphrase)
	path, err := bip32path.ParsePath(*pathString)
	if err != nil {
		log.Fatalf("invalid path (%s): %s", *pathString, err)
	}

	fmt.Println("==> Key Derivation Parameters")

	fmt.Printf(" entropy (%d-byte):\t%x\n", len(entropy), entropy)
	fmt.Printf(" mnemonic (%d-word):\t%s\n", len(mnemonic), mnemonic)
	fmt.Printf(" optional passphrase:\t\"%s\"\n", *passphrase)
	fmt.Printf(" master seed (%d-byte):\t%x\n", len(seed), seed)

	fmt.Println("\n==> Legacy IOTA Seed Derivation (Ledger App)")

	curve := slip10.Secp256k1()
	key, err := slip10.DeriveKeyFromPath(seed, curve, path)
	if err != nil {
		log.Fatalf("error deriving key: %s", err)
	}

	fmt.Printf(" SLIP-10 curve seed:\t%s\n", curve.SeedKey())
	fmt.Printf(" SLIP-10 address path:\t%s\n", path)

	fmt.Printf(" private key (%d-byte):\t%x\n", slip10.PrivateKeySize, key.Key)
	fmt.Printf(" chain code (%d-byte):\t%x\n", slip10.ChainCodeSize, key.ChainCode)
	fmt.Printf(" IOTA seed (%d-tryte):\t%s\n", consts.HashTrytesSize, iotaSeedFromKey(key))

	fmt.Println("\n==> Ed25519 Private Key Derivation")

	curve = slip10.Ed25519()
	key, err = slip10.DeriveKeyFromPath(seed, curve, path)
	if err != nil {
		log.Fatalf("error deriving key: %s", err)
	}

	fmt.Printf(" SLIP-10 curve seed:\t%s\n", curve.SeedKey())
	fmt.Printf(" SLIP-10 address path:\t%s\n", path)

	fmt.Printf(" private key (%d-byte):\t%x\n", slip10.PrivateKeySize, key.Key)
	fmt.Printf(" chain code (%d-byte):\t%x\n", slip10.ChainCodeSize, key.ChainCode)
	fmt.Printf(" public key (%d-byte):\t%x\n", slip10.PublicKeySize, curve.PublicKey(key))
}

func generateEntropy(size int) []byte {
	entropy := make([]byte, size)
	if _, err := rand.Read(entropy); err != nil {
		log.Fatalf("failed to generate entropy: %s", err)
	}
	return entropy
}

// Legacy IOTA seed derivation as implemented in the blue-app-iota:
// https://github.com/IOTA-Ledger/blue-app-iota/blob/master/docs/specification.md#iota-seed
func iotaSeedFromKey(key *slip10.Key) trinary.Hash {
	// the 512 bits extended private key (k, c) of the provided address path is then hashed using Kerl.
	hash := kerl.NewKerl()

	// as Kerl expects multiples of 48 bytes as input, the following 98 bytes are absorbed:
	// k[0:32] + c[0:16] + k[16:32] + c[0:32]
	var entropy []byte
	entropy = append(entropy, key.Key[0:32]...)
	entropy = append(entropy, key.ChainCode[0:16]...)
	entropy = append(entropy, key.Key[16:32]...)
	entropy = append(entropy, key.ChainCode[0:32]...)

	// absorb two chunks of 48 bytes
	in, _ := kerl.KerlBytesToTrytes(entropy[:consts.HashBytesSize])
	hash.MustAbsorbTrytes(in)
	in, _ = kerl.KerlBytesToTrytes(entropy[consts.HashBytesSize:])
	hash.MustAbsorbTrytes(in)

	// derive the the final 243 trit IOTA seed
	return hash.MustSqueezeTrytes(consts.HashTrinarySize)
}
