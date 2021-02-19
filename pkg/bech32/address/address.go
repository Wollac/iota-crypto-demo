// Package address provides utility functionality to encode and decode bech32 based addresses.
package address

import (
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/wollac/iota-crypto-demo/pkg/bech32"
	"github.com/wollac/iota-crypto-demo/pkg/ed25519"
	"golang.org/x/crypto/blake2b"
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
	hrpStrings = [...]string{"iota", "atoi"}
)

// Version denotes the version of an address.
type Version byte

// Supported address versions
const (
	Ed25519 Version = iota
)

func (v Version) String() string {
	return [...]string{"Ed25519"}[v]
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
	case Ed25519:
		if len(addrData) != blake2b.Size256 {
			return 0, nil, fmt.Errorf("invalid Ed25519 address: %w", ErrInvalidLength)
		}
		var addr Ed25519Address
		copy(addr.hash[:], addrData)
		return prefix, addr, nil
	}
	return 0, nil, fmt.Errorf("%w: %d", ErrInvalidVersion, version)
}

// Address specifies a general address of different underlying types.
type Address interface {
	Version() Version
	Bytes() []byte

	String() string
}

type Ed25519Address struct {
	hash [blake2b.Size256]byte
}

func (Ed25519Address) Version() Version {
	return Ed25519
}
func (a Ed25519Address) Bytes() []byte {
	return append([]byte{byte(Ed25519)}, a.hash[:]...)
}
func (a Ed25519Address) String() string {
	return hex.EncodeToString(a.hash[:])
}

// AddressFromPublicKey creates an address from a 32-byte hash.
func AddressFromPublicKey(key ed25519.PublicKey) Ed25519Address {
	if len(key) != ed25519.PublicKeySize {
		panic("invalid public key size")
	}
	return Ed25519Address{blake2b.Sum256(key)}
}
