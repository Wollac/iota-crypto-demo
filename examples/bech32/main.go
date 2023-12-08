package main

import (
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/iotaledger/iota-crypto-demo/internal/rand"
	"github.com/iotaledger/iota-crypto-demo/pkg/bech32"
	"github.com/iotaledger/iota-crypto-demo/pkg/bech32/address"
	"github.com/iotaledger/iota-crypto-demo/pkg/ed25519"
)

// default values
var (
	defPrefix    = address.IOTAMainnet
	defVersion   = address.Ed25519
	defPublicKey = func() ed25519.PublicKey {
		pub, _, _ := ed25519.GenerateKey(rand.Reader)
		return pub
	}()
	defBech32 = func() string {
		s, _ := address.Bech32(defPrefix, address.AddressFromPublicKey(defPublicKey))
		return s
	}()
)

var (
	encode        = flag.NewFlagSet("encode", flag.ExitOnError)
	prefixString  = encode.String("prefix", defPrefix.String(), "network prefix")
	versionString = encode.String("version", defVersion.String(), "address version")
	keyString     = encode.String("key", hex.EncodeToString(defPublicKey), "hex-encoded public key / output ID")

	decode        = flag.NewFlagSet("decode", flag.ExitOnError)
	addressString = decode.String("address", defBech32, "Bech32 encoded IOTA address")
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

	version, err := address.ParseVersion(*versionString)
	if err != nil {
		return fmt.Errorf("invalid address version: %w", err)
	}

	key, err := hex.DecodeString(*keyString)
	if err != nil {
		return fmt.Errorf("invalid key: %w", err)
	}

	var addr address.Address
	switch version {
	case address.Ed25519:
		if len(key) != ed25519.PublicKeySize {
			return fmt.Errorf("invalid pubblic key: length %d", len(key))
		}
		addr = address.AddressFromPublicKey(key)
	case address.Alias:
		if len(key) != address.OutputIDLength {
			return fmt.Errorf("invalid output ID: length %d", len(key))
		}
		var outputID [address.OutputIDLength]byte
		copy(outputID[:], key)
		addr = address.AliasAddressFromOutputID(outputID)
	case address.NFT:
		if len(key) != address.OutputIDLength {
			return fmt.Errorf("invalid output ID: length %d", len(key))
		}
		var outputID [address.OutputIDLength]byte
		copy(outputID[:], key)
		addr = address.NFTAddressFromOutputID(outputID)
	default:
		panic("invalid address version")
	}

	s, err := address.Bech32(prefix, addr)
	if err != nil {
		return err
	}

	fmt.Println("==> Bech32 Address Encoder")
	fmt.Printf("  public key (%d-byte):\t%x\n", len(key), key)
	fmt.Printf("  hash (%d-char):\t%s\n", len(addr.String()), addr.String())
	fmt.Printf("  addr bytes (%d-byte):\t%x\n", len(addr.Bytes()), addr.Bytes())
	fmt.Printf("  network (%d-char):\t%s\n", len(prefix.String()), prefix.String())
	fmt.Printf("  version (1-byte):\t0x%02x (%s)\n", uint(addr.Version()), addr.Version().String())
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
	fmt.Printf("  version (1-byte):\t0x%02x (%s)\n", uint(addr.Version()), addr.Version().String())
	fmt.Printf("  hash (%d-char):\t%s\n", len(addr.String()), addr.String())
	fmt.Printf("  addr bytes (%d-byte):\t%x\n", len(addr.Bytes()), addr.Bytes())
	return nil
}
