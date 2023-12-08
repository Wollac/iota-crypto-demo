// Package address provides utility functionality to encode and decode bech32 based addresses.
package address

import (
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/iotaledger/iota-crypto-demo/pkg/bech32"
	"github.com/iotaledger/iota-crypto-demo/pkg/ed25519"
	"golang.org/x/crypto/blake2b"
)

const (
	// OutputIDLength defines the length of an OutputID.
	OutputIDLength = blake2b.Size256 + 2
	// Blake2b160Length defines the size of a BLAKE2b-160 hash in bytes.
	Blake2b160Length = 20
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
	IOTAMainnet Prefix = iota
	IOTADevnet
	ShimmerMainnet
	ShimmerDevnet
)

var hrpStrings = [...]string{"iota", "atoi", "smr", "rms"}

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

// Version denotes the version of an address.
type Version byte

// Supported address versions
const (
	Ed25519 Version = 0x00
	Alias   Version = 0x08
	NFT     Version = 0x10
)

var versionStrings = map[Version]string{0x00: "Ed25519", 0x08: "Alias", 0x10: "NFT"}

func (v Version) String() string {
	return versionStrings[v]
}

func ParseVersion(s string) (Version, error) {
	for v, versionString := range versionStrings {
		if s == versionString {
			return v, nil
		}
	}
	return 0, ErrInvalidVersion
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
	case Alias:
		if len(addrData) != Blake2b160Length {
			return 0, nil, fmt.Errorf("invalid Alias address: %w", ErrInvalidLength)
		}
		var addr AliasAddress
		copy(addr.hash[:], addrData)
		return prefix, addr, nil
	case NFT:
		if len(addrData) != Blake2b160Length {
			return 0, nil, fmt.Errorf("invalid NFT address: %w", ErrInvalidLength)
		}
		var addr NFTAddress
		copy(addr.hash[:], addrData)
		return prefix, addr, nil
	}
	return 0, nil, fmt.Errorf("%w: %d", ErrInvalidVersion, version)
}

func blake2bSum160(b []byte) [Blake2b160Length]byte {
	h, err := blake2b.New(Blake2b160Length, nil)
	if err != nil {
		panic(err)
	}
	_, err = h.Write(b)
	if err != nil {
		panic(err)
	}
	var sum160 [Blake2b160Length]byte
	copy(sum160[:], h.Sum(nil))
	return sum160
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

type AliasAddress struct {
	hash [Blake2b160Length]byte
}

func (AliasAddress) Version() Version {
	return Alias
}
func (a AliasAddress) Bytes() []byte {
	return append([]byte{byte(Alias)}, a.hash[:]...)
}
func (a AliasAddress) String() string {
	return hex.EncodeToString(a.hash[:])
}

// AliasAddressFromOutputID returns the alias address computed from a given OutputID.
func AliasAddressFromOutputID(outputID [OutputIDLength]byte) AliasAddress {
	return AliasAddress{blake2bSum160(outputID[:])}
}

type NFTAddress struct {
	hash [Blake2b160Length]byte
}

func (NFTAddress) Version() Version {
	return NFT
}
func (a NFTAddress) Bytes() []byte {
	return append([]byte{byte(NFT)}, a.hash[:]...)
}
func (a NFTAddress) String() string {
	return hex.EncodeToString(a.hash[:])
}

// NFTAddressFromOutputID returns the alias address computed from a given OutputID.
func NFTAddressFromOutputID(outputID [OutputIDLength]byte) NFTAddress {
	return NFTAddress{blake2bSum160(outputID[:])}
}
