package main

import (
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/wollac/iota-bip39-demo/pkg/bech32"
	"github.com/wollac/iota-bip39-demo/pkg/bech32/address"
)

// default values
var (
	defPrefix = address.Mainnet
	defWOTS   = func() address.Address {
		addr, _ := address.WOTSAddress("EQSAUZXULTTYZCLNJNTXQTQHOMOFZERHTCGTXOLTVAHKSA9OGAZDEKECURBRIXIJWNPFCQIOVFVVXJVD9")
		return addr
	}()
	defBech32 = func() string {
		addr, _ := address.Ed25519Address([]byte{82, 253, 252, 7, 33, 130, 101, 79, 22, 63, 95, 15, 154, 98, 29, 114, 149, 102, 199, 77, 16, 3, 124, 77, 123, 187, 4, 7, 209, 226, 198, 73})
		s, _ := address.Bech32(defPrefix, addr)
		return s
	}()
)

var (
	encode       = flag.NewFlagSet("encode", flag.ExitOnError)
	hashString   = encode.String("hash", defWOTS.String(), "tryte-encoded W-OTS hash or hex-encoded binary hash")
	prefixString = encode.String("prefix", defPrefix.String(), "network prefix")

	decode        = flag.NewFlagSet("decode", flag.ExitOnError)
	addressString = decode.String("address", defBech32, "bech32 encoded IOTA address")
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
	fmt.Printf("\t%s\tencode a bech32 address\n", encode.Name())
	fmt.Printf("\t%s\tdecode a bech32 address\n\n", decode.Name())
	os.Exit(2)
}

func runEncode(arguments []string) error {
	err := encode.Parse(arguments)
	if err != nil {
		return err
	}
	prefix, err := address.ParsePrefix(*prefixString)
	if err != nil {
		return fmt.Errorf("invalid prefix: %w", err)
	}

	var addr address.Address
	switch len(*hashString) {
	case 81:
		fallthrough
	case 90:
		addr, err = address.WOTSAddress(*hashString)
		if err != nil {
			return err
		}
	default:
		bytes, err := hex.DecodeString(*hashString)
		if err != nil {
			return err
		}
		addr, err = address.Ed25519Address(bytes)
		if err != nil {
			return err
		}
	}

	s, err := address.Bech32(prefix, addr)
	if err != nil {
		return err
	}

	fmt.Println("==> Bech32 Address Encoder")
	fmt.Printf("  hash (%d-char):\t%s\n", len(addr.String()), addr.String())
	fmt.Printf("  addr bytes (%d-byte):\t%x\n", len(addr.Bytes()), addr.Bytes())
	fmt.Printf("  network (%d-char):\t%s\n", len(prefix.String()), prefix.String())
	fmt.Printf("  version (1-byte):\t%b (%s)\n", addr.Version(), addr.Version().String())
	fmt.Printf("  bech32 (%d-char):\t%s\n", len(s), s)
	fmt.Printf("    checksum\t\t%s\n", strings.Repeat(" ", len(s)-6)+strings.Repeat("^", 6))
	return nil
}

func runDecode(arguments []string) error {
	if err := decode.Parse(arguments); err != nil {
		return err
	}

	fmt.Println("==> Bech32 Address Decoder")
	fmt.Printf("  bech32 (%d-char):\t%s\n", len(*addressString), *addressString)
	prefix, addr, err := address.ParseBech32(*addressString)
	if err != nil {
		var e *bech32.SyntaxError
		if errors.As(err, &e) {
			fmt.Println("\t\t\t" + strings.Repeat(" ", e.Offset) + "^")
		}
		return err
	}

	fmt.Printf("  network (%d-char):\t%s\n", len(prefix.String()), prefix.String())
	fmt.Printf("  version (1-byte):\t%b (%s)\n", addr.Version(), addr.Version().String())
	fmt.Printf("  hash (%d-char):\t%s\n", len(addr.String()), addr.String())
	fmt.Printf("  addr bytes (%d-byte):\t%x\n", len(addr.Bytes()), addr.Bytes())
	return nil
}
