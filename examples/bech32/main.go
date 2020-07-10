package main

import (
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/iotaledger/iota.go/address"
	"github.com/iotaledger/iota.go/consts"
	"github.com/iotaledger/iota.go/kerl"
	"github.com/iotaledger/iota.go/trinary"
	"github.com/wollac/iota-bip39-demo/pkg/bech32"
)

var (
	encode = flag.NewFlagSet("encode", flag.ExitOnError)
	hash   = encode.String(
		"hash",
		"EQSAUZXULTTYZCLNJNTXQTQHOMOFZERHTCGTXOLTVAHKSA9OGAZDEKECURBRIXIJWNPFCQIOVFVVXJVD9DGCJRJTHZ",
		"WOTS or hex hash to encode in the address",
	)

	decode = flag.NewFlagSet("decode", flag.ExitOnError)
	addr   = decode.String(
		"addr",
		"iota1qy84dkjj6ugcheyc98d6dvgf2szjkzr7yyma8vje5neng0h5ggpxgz88uep",
		"bech32 address",
	)
)

var (
	prefix       = "iota"
	encodeTrytes = kerl.KerlTrytesToBytes
	//encodeTrytes = func(hash trinary.Hash) ([]byte, error) {
	//	trits, err := trinary.TrytesToTrits(hash)
	//	if err != nil {
	//		return nil, err
	//	}
	//	return t5b1.Encode(trits), nil
	//}
	decodeTrytes = kerl.KerlBytesToTrytes
	//decodeTrytes = func(bytes []byte) (trinary.Trytes, error) {
	//	trits, err := t5b1.Decode(bytes)
	//	if err != nil {
	//		return "", err
	//	}
	//	return trinary.MustTritsToTrytes(trits[:243]), nil
	//}
)

func main() {
	if len(os.Args) < 2 {
		help()
	}

	switch os.Args[1] {
	case encode.Name():
		if err := runEncode(os.Args[2:]); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %s\n", err)
			os.Exit(1)
		}
	case decode.Name():
		if err := runDecode(os.Args[2:]); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %s\n", err)
			os.Exit(1)
		}
	default:
		help()
	}
}

func help() {
	fmt.Printf("Usage of %s:\n", os.Args[0])
	fmt.Printf("\t<command> [arguments]\n\n")
	fmt.Printf("The commands are:\n")
	fmt.Printf("\t%s\tencode an address\n", encode.Name())
	fmt.Printf("\t%s\tdecode an address\n\n", decode.Name())
	os.Exit(2)
}

func runEncode(arguments []string) error {
	if err := encode.Parse(arguments); err != nil {
		return err
	}

	var (
		data    []byte
		version string
	)
	switch len(*hash) {
	case 81:
		fallthrough
	case 90:
		if err := validateWOTSAddress(*hash); err != nil {
			return err
		}
		bytes, err := encodeTrytes((*hash)[:81])
		if err != nil {
			return err
		}
		data = append([]byte{0}, bytes...)
		version = "WOTS"
	default:
		bytes, err := hex.DecodeString(*hash)
		if err != nil {
			return err
		}
		data = append([]byte{1}, bytes...)
		version = "Ed25519"
	}

	addr, err := bech32.Encode(prefix, data)
	if err != nil {
		return err
	}

	fmt.Println("==> Bech32 Address Encoder")
	fmt.Printf("  hash (%d-char):\t%s\n", len(*hash), *hash)
	fmt.Printf("  network (%d-byte):\t%s\n", len(prefix), prefix)
	fmt.Printf("  version (1-byte):\t%s\n", version)
	fmt.Printf("  address (%d-byte):\t%s\n", len(addr), addr)
	fmt.Printf("    HRP\t\t\t%s\n", strings.Repeat("^", len(prefix)))
	fmt.Printf("    separator\t\t%s\n", strings.Repeat(" ", len(prefix))+"^")
	fmt.Printf("    checksum\t\t%s\n", strings.Repeat(" ", len(addr)-6)+strings.Repeat("^", 6))
	return nil
}

func runDecode(arguments []string) error {
	if err := decode.Parse(arguments); err != nil {
		return err
	}

	fmt.Println("==> Bech32 Address Decoder")
	fmt.Printf("  address (%d-byte):\t%s\n", len(*addr), *addr)
	hrp, data, err := bech32.Decode(*addr)
	if err != nil {
		var e *bech32.SyntaxError
		if errors.As(err, &e) {
			fmt.Println("\t\t\t" + strings.Repeat(" ", e.Offset) + "^")
		}
		return err
	}

	fmt.Printf("  network (%d-byte):\t%s\n", len(hrp), hrp)
	switch data[0] {
	case 0:
		fmt.Printf("  version (1-byte):\t%s\n", "WOTS")
		hash, err := decodeTrytes(data[1:])
		if err != nil {
			return err
		}
		fmt.Printf("  hash (%d-tryte):\t%s\n", len(hash), hash)
	case 1:
		fmt.Printf("  version (1-byte):\t%s\n", "Ed25519")
		fmt.Printf("  hash (%d-tryte):\t%x\n", len(data[1:]), data[1:])
	default:
		return fmt.Errorf("invalid version: %d", data[0])
	}

	return nil
}

func validateWOTSAddress(hash trinary.Hash) error {
	if err := address.ValidAddress(hash); err != nil {
		return err
	}
	// a valid hash must have the last trit set to zero
	lastTrits := trinary.MustTrytesToTrits(string(hash[consts.HashTrytesSize-1]))
	if lastTrits[consts.TritsPerTryte-1] != 0 {
		return consts.ErrInvalidHash
	}
	return nil
}
