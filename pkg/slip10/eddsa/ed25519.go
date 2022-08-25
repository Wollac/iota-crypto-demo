package eddsa

import (
	"errors"

	"github.com/wollac/iota-crypto-demo/pkg/ed25519"
	"github.com/wollac/iota-crypto-demo/pkg/slip10"
)

// ErrNotHardened is returned when the input led to an invalid private or public key.
var ErrNotHardened = errors.New("only hardened derivation is supported")

type ed25519Curve struct{}

// Ed25519 returns a slip10.Curve which implements the Ed25519 signature algorithm. See https://ed25519.cr.yp.to/.
func Ed25519() slip10.Curve {
	return ed25519Curve{}
}

func (ed25519Curve) NewPrivateKey(buf []byte) (slip10.Key, error) {
	if len(buf) != ed25519.SeedSize {
		panic("invalid buffer length")
	}

	// RFC 8032's private keys correspond to seeds in stdlib
	seed := make([]byte, ed25519.SeedSize)
	copy(seed, buf)
	return Seed(seed), nil
}

func (ed25519Curve) Name() string {
	return "ed25519"
}

func (ed25519Curve) HmacKey() []byte {
	return []byte("ed25519 seed")
}

// Seed implements slip10.Key and represents an Ed25519 seed.
// RFC 8032's private keys correspond to seeds in this package.
type Seed []byte

// Bytes returns the SLIP-10 serialization of the key.
func (s Seed) Bytes() []byte {
	return s
}

// IsPrivate always returns true.
func (Seed) IsPrivate() bool {
	return true
}

// Public returns the corresponding PublicKey.
func (s Seed) Public() slip10.Key {
	priv := ed25519.NewKeyFromSeed(s)
	return PublicKey(priv.Public().(ed25519.PublicKey))
}

// Shift derives a new Seed from the provided bytes.
func (Seed) Shift(buf []byte) (slip10.Key, error) {
	if len(buf) != ed25519.SeedSize {
		panic("invalid buffer length")
	}

	seed := make([]byte, ed25519.SeedSize)
	copy(seed, buf)
	return Seed(seed), nil
}

// Ed25519Key generates the corresponding public/private key pair.
func (s Seed) Ed25519Key() (ed25519.PublicKey, ed25519.PrivateKey) {
	privateKey := ed25519.NewKeyFromSeed(s.Bytes())
	return privateKey.Public().(ed25519.PublicKey), privateKey
}

// PublicKey implements slip10.Key and represents an Ed25519 public key.
type PublicKey ed25519.PublicKey

// Bytes returns the SLIP-10 serialization of the key.
func (p PublicKey) Bytes() []byte {
	buf := make([]byte, slip10.PublicKeySize)
	copy(buf[slip10.PublicKeySize-len(p):], p)
	return buf
}

// IsPrivate always returns false.
func (PublicKey) IsPrivate() bool {
	return false
}

// Public returns a reference to itself.
func (p PublicKey) Public() slip10.Key {
	return p
}

// Shift implements the Shift method of slip10.Key.
func (PublicKey) Shift([]byte) (slip10.Key, error) {
	// as Ed25519 only supports hardened derivation, this is not supported
	return nil, ErrNotHardened
}
