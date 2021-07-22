package main

import (
	"crypto/rand"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/iotaledger/iota.go/consts"
	"github.com/iotaledger/iota.go/kerl"
	"github.com/iotaledger/iota.go/kerl/sha3"
	"github.com/iotaledger/iota.go/trinary"
	"github.com/wollac/iota-crypto-demo/pkg/bech32/address"
	"github.com/wollac/iota-crypto-demo/pkg/bip32path"
	"github.com/wollac/iota-crypto-demo/pkg/bip39"
	"github.com/wollac/iota-crypto-demo/pkg/slip10"
)

var (
	mnemonicString = flag.String(
		"mnemonic",
		"abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
		"mnemonic sentence according to BIP-39, 12-48 words are supported; if empty a random entropy is generated",
	)
	language = flag.String(
		"language",
		"english",
		"language of the mnemonics",
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
	prefixString = flag.String(
		"prefix",
		address.Mainnet.String(),
		"network prefix used for the Ed25519 address",
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
	var (
		err      error
		entropy  []byte
		mnemonic bip39.Mnemonic
	)

	if err := bip39.SetWordList(strings.ToLower(*language)); err != nil {
		return err
	}
	if len(*mnemonicString) == 0 {
		// no mnemonic given, generate
		entropy, err = generateEntropy(256 / 8 /* 256 bits */)
		if err != nil {
			return fmt.Errorf("failed generating entropy: %w", err)
		}
		mnemonic, _ = bip39.EntropyToMnemonic(entropy)
	} else {
		mnemonic = bip39.ParseMnemonic(*mnemonicString)
		entropy, err = bip39.MnemonicToEntropy(mnemonic)
		if err != nil {
			return fmt.Errorf("invalid path: %w", err)
		}
	}

	seed, _ := bip39.MnemonicToSeed(mnemonic, *passphrase)
	path, err := bip32path.ParsePath(*pathString)
	if err != nil {
		return fmt.Errorf("invalid path: %w", err)
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
		return fmt.Errorf("failed deriving %s key: %w", curve.Name(), err)
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
		return fmt.Errorf("failed deriving %s key: %w", curve.Name(), err)
	}
	hrp, err := address.ParsePrefix(*prefixString)
	if err != nil {
		return fmt.Errorf("invalid network prefix: %w", err)
	}
	public, _ := slip10.Ed25519Key(key)
	addr, err := address.Bech32(hrp, address.AddressFromPublicKey(public))
	if err != nil {
		return fmt.Errorf("failed to encode address with %s prefix: %w", hrp, err)
	}

	fmt.Printf(" SLIP-10 curve seed:\t%s\n", curve.SeedKey())
	fmt.Printf(" SLIP-10 address path:\t%s\n", path)

	fmt.Printf(" private key (%d-byte):\t%x\n", slip10.PrivateKeySize, key.Key)
	fmt.Printf(" chain code (%d-byte):\t%x\n", slip10.ChainCodeSize, key.ChainCode)
	fmt.Printf(" address (%d-char):\t%s\n", len(addr), addr)

	return nil
}

func generateEntropy(size int) ([]byte, error) {
	entropy := make([]byte, size)
	if _, err := rand.Read(entropy); err != nil {
		return nil, err
	}
	return entropy, nil
}

// Legacy IOTA seed derivation as implemented in the blue-app-iota:
// https://github.com/IOTA-Ledger/blue-app-iota/blob/master/docs/specification.md#iota-seed
func iotaSeedFromKey(key *slip10.Key) trinary.Hash {
	// the 512 bits extended private key (k, c) of the provided address path is then hashed using Keccak-384.
	hash := sha3.NewLegacyKeccak384()

	// as Kerl usually expects multiples of 48 bytes as input, the following 98 bytes are absorbed:
	// k[0:32] + c[0:16] + k[16:32] + c[0:32]
	hash.Write(key.Key[0:32])
	hash.Write(key.ChainCode[0:16])
	hash.Write(key.Key[16:32])
	hash.Write(key.ChainCode[0:32])

	// derive the the final 243 trit IOTA seed from the resulting hash
	seed, err := kerl.KerlBytesToTrytes(hash.Sum(nil))
	if err != nil {
		panic(err)
	}
	return seed
}
