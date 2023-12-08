package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"os"

	"github.com/iotaledger/iota-crypto-demo/internal/rand"
	"github.com/iotaledger/iota-crypto-demo/pkg/ed25519"
	"github.com/iotaledger/iota-crypto-demo/pkg/migration"
	"github.com/iotaledger/iota.go/checksum"
	"github.com/iotaledger/iota.go/consts"
	"golang.org/x/crypto/blake2b"
)

var (
	ed25519Address = flag.String(
		"address",
		"",
		"Ed25519 address as hex; if empty a new random address is generated",
	)
)

func main() {
	flag.Parse()

	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %s\n", err)
		os.Exit(1)
	}
}

func run() (err error) {
	if len(*ed25519Address) == 0 {
		*ed25519Address, err = randomAddress()
		if err != nil {
			return err
		}
	}
	addressBytes, err := hex.DecodeString(*ed25519Address)
	if err != nil {
		return fmt.Errorf("failed to decode address: %w", err)
	}

	var addr [32]byte
	copy(addr[:], addressBytes)
	migAddr, err := checksum.AddChecksum(migration.Encode(addr), true, consts.AddressChecksumTrytesSize)
	if err != nil {
		return fmt.Errorf("failed to compute address checksum: %w", err)
	}

	fmt.Println("==> Migration Address Encoder")
	fmt.Printf("  Ed25519 address (%d-byte):\t%s\n", len(addr), hex.EncodeToString(addr[:]))
	fmt.Printf("  Migration address (%d-tryte):\t%s\n", len(migAddr), migAddr)

	return nil
}

func randomAddress() (string, error) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", err
	}
	hash := blake2b.Sum256(pub)
	return hex.EncodeToString(hash[:]), nil
}
