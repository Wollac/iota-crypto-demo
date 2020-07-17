// Package address provides utility functionality to encode and decode bech32 based addresses.
package address

import (
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/iotaledger/iota.go/address"
	"github.com/iotaledger/iota.go/consts"
	"github.com/iotaledger/iota.go/trinary"
	"github.com/wollac/iota-crypto-demo/pkg/bech32"
	"github.com/wollac/iota-crypto-demo/pkg/encoding/t5b1"
)

// Errors returned during address parsing.
var (
	ErrInvalidPrefix  = errors.New("invalid prefix")
	ErrInvalidVersion = errors.New("invalid version")
	ErrInvalidLength  = errors.New("invalid length")
)

// Prefix denotes the different network prefixes.
type Prefix int

// Network prefix options
const (
	Mainnet Prefix = iota
	Devnet
)

func (p Prefix) String() string {
	return hrpStrings[p]
}

func ParsePrefix(s string) (Prefix, error) {
	for i := range hrpStrings {
		if s == hrpStrings[i] {
			return Prefix(i), nil
		}
	}
	return 0, ErrInvalidPrefix
}

var (
	hrpStrings = [...]string{"iot", "tio"}
)

// Version denotes the version of an address.
type Version byte

// Supported address versions
const (
	WOTS Version = iota
	Ed25519
)

func (v Version) String() string {
	return [...]string{"WOTS", "Ed25519"}[v]
}

// Bech32 encodes the provided addr as a bech32 string.
func Bech32(hrp Prefix, addr Address) (string, error) {
	return bech32.Encode(hrp.String(), addr.Bytes())
}

// ParseBech32 decodes a bech32 encoded string.
func ParseBech32(s string) (Prefix, Address, error) {
	hrp, addrData, err := bech32.Decode(s)
	if err != nil {
		return 0, nil, fmt.Errorf("invalid bech32 encoding: %w", err)
	}
	prefix, err := ParsePrefix(hrp)
	if err != nil {
		return 0, nil, fmt.Errorf("invalid human-readable prefix: %w", err)
	}
	if len(addrData) == 0 {
		return 0, nil, fmt.Errorf("%w: no version", ErrInvalidVersion)
	}
	version := Version(addrData[0])
	addrData = addrData[1:]
	switch version {
	case WOTS:
		hash, err := t5b1.DecodeToTrytes(addrData)
		if err != nil {
			return 0, nil, fmt.Errorf("invalid WOTS address: %w", err)
		}
		addr, err := WOTSAddress(hash)
		if err != nil {
			return 0, nil, fmt.Errorf("invalid wotsAddress address: %w", err)
		}
		return prefix, addr, nil
	case Ed25519:
		addr, err := Ed25519Address(addrData)
		if err != nil {
			return 0, nil, fmt.Errorf("invalid Ed25519 address: %w", err)
		}
		return prefix, addr, nil
	}
	return 0, nil, fmt.Errorf("%w: %d", ErrInvalidVersion, version)
}

func validateHash(hash trinary.Hash) error {
	if err := address.ValidAddress(hash); err != nil {
		return err
	}
	// a valid addresses must have the last trit set to zero
	lastTrits := trinary.MustTrytesToTrits(string(hash[consts.HashTrytesSize-1]))
	if lastTrits[consts.TritsPerTryte-1] != 0 {
		return fmt.Errorf("%w: non-zero last trit", consts.ErrInvalidAddress)
	}
	return nil
}

// Address specifies a general address of different underlying types.
type Address interface {
	Version() Version
	Bytes() []byte

	String() string
}

type wotsAddress trinary.Hash

func (wotsAddress) Version() Version {
	return WOTS
}
func (a wotsAddress) Bytes() []byte {
	return append([]byte{byte(WOTS)}, t5b1.EncodeTrytes(trinary.Trytes(a))...)
}
func (a wotsAddress) String() string {
	return string(a)
}

// WOTSAddress creates an Address from the provided W-OTS hash.
func WOTSAddress(hash trinary.Hash) (Address, error) {
	err := validateHash(hash)
	if err != nil {
		return nil, err
	}
	return wotsAddress(hash[:consts.HashTrytesSize]), nil
}

type ed25519Address [32]byte

func (ed25519Address) Version() Version {
	return Ed25519
}
func (a ed25519Address) Bytes() []byte {
	return append([]byte{byte(Ed25519)}, a[:]...)
}
func (a ed25519Address) String() string {
	return hex.EncodeToString(a[:])
}

// Ed25519Address creates an address from a 32-byte hash.
func Ed25519Address(hash []byte) (Address, error) {
	var addr ed25519Address
	if len(hash) != len(addr) {
		return nil, ErrInvalidLength
	}
	copy(addr[:], hash)
	return addr, nil
}
