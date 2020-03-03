package slip10

import (
	ed25519crypt "crypto/ed25519"
	"crypto/elliptic"
	"errors"
	"math/big"

	"github.com/wollac/iota-bip39-demo/pkg/slip10/btccurve"
)

// Errors returned by the key derivation.
var (
	ErrInvalidPrivateKey = errors.New("invalid private key")
	ErrNotHardened       = errors.New("only hardened key generation supported")
)

// A Curve represents a curve type to derive private and public key pairs for.
type Curve interface {
	// SeedKey returns the HMAC key used for the master key generation.
	SeedKey() []byte
	// ValidateChildIndex checks whether the given child index leads to a valid key derivation.
	ValidateChildIndex(index uint32) error
	// PrivateKey computes the private key from the intermediate secret key and the private key of the parent.
	// If this leads to an infeasible private key an error is returned.
	PrivateKey(interKey []byte, parentKey []byte) ([]byte, error)
	// PublicKey computes the public key from the given extended private key.
	PublicKey(key *Key) []byte
}

type ellipticCurve struct {
	elliptic.Curve
}

func (ellipticCurve) ValidateChildIndex(index uint32) error {
	return nil
}

func (e *ellipticCurve) PrivateKey(interKey []byte, parentKey []byte) ([]byte, error) {
	var a, b big.Int
	a.SetBytes(interKey)
	if a.Cmp(e.Params().N) >= 0 {
		return nil, ErrInvalidPrivateKey
	}
	b.SetBytes(parentKey)

	a.Add(&a, &b)
	a.Mod(&a, e.Params().N)

	if a.Sign() == 0 {
		return nil, ErrInvalidPrivateKey
	}

	result := make([]byte, PrivateKeySize)
	aBytes := a.Bytes()
	copy(result[PrivateKeySize-len(aBytes):], aBytes)
	return result, nil
}

func (e *ellipticCurve) PublicKey(key *Key) []byte {
	x, y := e.ScalarBaseMult(key.Key)
	return marshallCompressed(e, x, y)
}

// marshallCompressed converts a point into the compressed form specified in section 2.3.3 in SEC1.
func marshallCompressed(curve elliptic.Curve, x, y *big.Int) []byte {
	byteLen := (curve.Params().BitSize + 7) >> 3

	result := make([]byte, 1+byteLen)
	result[0] = byte(0x2) + byte(y.Bit(0))

	xBytes := x.Bytes()
	copy(result[1+byteLen-len(xBytes):], xBytes)
	return result
}

type secp256k1Curve struct {
	ellipticCurve
}

func (secp256k1Curve) SeedKey() []byte {
	return []byte("Bitcoin seed")
}

type nist256p1Curve struct {
	ellipticCurve
}

func (nist256p1Curve) SeedKey() []byte {
	return []byte("Nist256p1 seed")
}

type ed25519Curve struct{}

func (ed25519Curve) SeedKey() []byte {
	return []byte("ed25519 seed")
}

func (ed25519Curve) ValidateChildIndex(index uint32) error {
	// ed25519 only supports hardened indices, as public key -> public key derivation is not supported.
	if index < hardened {
		return ErrNotHardened
	}
	return nil
}

func (ed25519Curve) PrivateKey(interKey []byte, parentKey []byte) ([]byte, error) {
	return interKey, nil
}

func (ed25519Curve) PublicKey(key *Key) []byte {
	// match the required public key size
	result := make([]byte, PublicKeySize)
	public := ed25519crypt.NewKeyFromSeed(key.Key).Public().(ed25519crypt.PublicKey)
	copy(result[PublicKeySize-len(public):], public)
	return result
}

var secp256k1 = &secp256k1Curve{ellipticCurve{btccurve.Secp256k1()}}
var nist256p1 = &nist256p1Curve{ellipticCurve{elliptic.P256()}}
var ed25519 = ed25519Curve{}

// Secp256k1 returns a Curve which implements secp256k1 (SEC 2, section 2.4.1).
func Secp256k1() Curve {
	return secp256k1
}

// Nist256p1 returns a Curve which implements NIST P-256 (FIPS 186-3, section D.2.3).
func Nist256p1() Curve {
	return nist256p1
}

// Ed25519 returns a Curve which implements the Ed25519 signature algorithm. See https://ed25519.cr.yp.to/.
func Ed25519() Curve {
	return ed25519
}
