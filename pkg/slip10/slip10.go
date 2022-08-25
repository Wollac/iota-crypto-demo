/*
Package slip10 implements the SLIP-0010 private key derivation.
It only supports the private parent key → private child key derivation for the
following curves:

	secp256k1 curve
	NIST P-256 curve
	ed25519 curve

The public key of an SLIP-0010 extended private key can be computed using
Curve.Public.

SLIP-0010 provides an extension of BIP-0032. As such, when the secp256k1 curve
is selected this package is fully compatible to the corresponding derivations
described in BIP-0032.

This package is tested against the test vectors provided in the official
SLIP-0010 specification.
*/
package slip10

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"

	"golang.org/x/crypto/ripemd160" //nolint:staticcheck,deprecated
)

const (
	// FingerprintSize is the size, in bytes, of the key fingerprint.
	FingerprintSize = 4
	// ChainCodeSize is the size, in bytes, of the chain code.
	ChainCodeSize = 32
	// PrivateKeySize is the size, in bytes, of the normal private key.
	PrivateKeySize = 32
	// PublicKeySize is the size, in bytes, of the normal public key.
	PublicKeySize = 33

	// Hardened returns the first hardened index.
	Hardened uint32 = 1 << 31
)

// ErrInvalidKey is returned when the input led to an invalid private or public key.
var ErrInvalidKey = errors.New("invalid key")

// ErrHardenedChildPublicKey is returned when ExtendedKey.DeriveChild is called with a hardened index on a public key.
var ErrHardenedChildPublicKey = errors.New("cannot create hardened child from public parent key")

// ExtendedKey represents a SLIP-10 extended private or public key.
type ExtendedKey struct {
	ChainCode []byte
	Key       Key

	parent Key // the parent key needed for the fingerprint computation
}

// A Curve represents a curve type to derive private and public key pairs for.
type Curve interface {
	// Name returns the canonical name of the curve.
	Name() string

	// HmacKey returns the HMAC key used for the master key generation.
	HmacKey() []byte

	// NewPrivateKey generates a private key based on buf.
	// If an ErrInvalidKey is returned, generation will be retried with a different buf.
	// Any other errors are considered permanent and returned to the caller.
	NewPrivateKey(buf []byte) (Key, error)
}

// A Key represents a private or public key for a curve.
type Key interface {
	// Bytes serializes the key as a byte slice.
	// The number of bytes must match PrivateKeySize or PublicKeySize respectively.
	Bytes() []byte

	// IsPrivate returns whether the key corresponds to a private or public key.
	IsPrivate() bool

	// Public returns the corresponding public key.
	Public() Key

	// Shift derives a new key using the provided additive shift.
	// It must not modify the receiver.
	// If an ErrInvalidKey is returned, generation will be retried with a different shift.
	// Any other errors are considered permanent and returned to the caller.
	Shift([]byte) (Key, error)
}

// NewMasterKey creates a new master private extended key for the curve from a seed.
func NewMasterKey(seed []byte, curve Curve) (*ExtendedKey, error) {
	inter := make([]byte, 0, 64)

step1:
	// Calculate I ← HMAC-SHA512(Key = Curve, Data = seed)
	h, err := hmacSHA512(curve.HmacKey(), seed)
	if err != nil {
		return nil, err
	}
	inter = h.Sum(inter[:0])

	// Split I into two 32-byte sequences, I_L and I_R
	left := inter[:32]
	right := inter[32:]

	// Use parse256(I_L) as secret key
	key, err := curve.NewPrivateKey(left)
	// If the secret key is invalid, set S ← I and recompute I
	if err != nil {
		seed = inter
		goto step1
	}

	// use I_R as chain code
	chainCode := right

	return &ExtendedKey{
		ChainCode: chainCode,
		Key:       key,
		parent:    nil,
	}, nil
}

// DeriveKeyFromPath derives an extended private key for the curve from seed and path as outlined by SLIP-10.
func DeriveKeyFromPath(seed []byte, curve Curve, path []uint32) (*ExtendedKey, error) {
	key, err := NewMasterKey(seed, curve)
	if err != nil {
		return nil, fmt.Errorf("failed to generate master key: %w", err)
	}
	for _, childIndex := range path {
		key, err = key.DeriveChild(childIndex)
		if err != nil {
			return nil, fmt.Errorf("failed to derive child key: %w", err)
		}
	}
	return key, nil
}

// DeriveChild derives an extended key from a given parent extended key as outlined by SLIP-10.
// If the parent is an extended public key, the child will also be an extended public key.
func (e *ExtendedKey) DeriveChild(index uint32) (*ExtendedKey, error) {
	inter := make([]byte, 0, 64)

	// Check whether i ≥ 2³¹ (whether the child is a Hardened key)
	if index >= Hardened {
		// CKDpub is only defined for non-Hardened child keys
		if !e.IsPrivate() {
			return nil, ErrHardenedChildPublicKey
		}

		// I ← HMAC-SHA512(Key = chain_par, Data = 0x00 || ser256(key_par) || ser32(index))
		h, err := hmacSHA512(e.ChainCode, []byte{0x00}, e.Key.Bytes(), uint32Bytes(index))
		if err != nil {
			return nil, err
		}
		inter = h.Sum(inter[:0])
	} else {
		// I = HMAC-SHA512(Key = chain_par, Data = ser_P(public_par) || ser32(index)),
		// where public_par = key_par if par is a public key, or public_par = point(key_par) otherwise
		h, err := hmacSHA512(e.ChainCode, e.Key.Public().Bytes(), uint32Bytes(index))
		if err != nil {
			return nil, err
		}
		inter = h.Sum(inter[:0])
	}

step2:
	// Split I into two 32-byte sequences, I_L and I_R
	left := inter[:32]
	right := inter[32:]

	// Compute the child key from I_L and key_par
	childKey, err := e.Key.Shift(left)
	// if the resulting key is invalid, recompute
	if errors.Is(err, ErrInvalidKey) {
		// Set I ← HMAC-SHA512(Key = chain_par, Data = 0x01 || I_R || ser32(index)) and restart at step 2
		h, err := hmacSHA512(e.ChainCode, []byte{0x01}, right, uint32Bytes(index))
		if err != nil {
			return nil, err
		}
		inter = h.Sum(inter[:0])

		goto step2
	}
	if err != nil {
		return nil, fmt.Errorf("failed to derive the child key: %w", err)
	}

	// The returned chain code is I_R
	chainCode := right

	return &ExtendedKey{
		ChainCode: chainCode,
		Key:       childKey,
		parent:    e.Key,
	}, nil
}

// IsPrivate returns whether the key is an extended private key or extended public key.
func (e *ExtendedKey) IsPrivate() bool {
	return e.Key.IsPrivate()
}

// Public returns the public version of key.
// If key is already an extended public key, a copy is returned.
func (e *ExtendedKey) Public() *ExtendedKey {
	return &ExtendedKey{
		ChainCode: e.ChainCode,
		Key:       e.Key.Public(),
		parent:    e.parent,
	}
}

// Fingerprint returns the fingerprint of the parent's key.
func (e *ExtendedKey) Fingerprint() []byte {
	if e.parent == nil {
		return make([]byte, FingerprintSize)
	}
	parentBytes := e.parent.Public().Bytes()
	return hash160(parentBytes)[:FingerprintSize]
}

func uint32Bytes(i uint32) []byte {
	bytes := make([]byte, 4)
	binary.BigEndian.PutUint32(bytes, i)
	return bytes
}

func hmacSHA512(key []byte, data ...[]byte) (hash.Hash, error) {
	h := hmac.New(sha512.New, key)
	for _, p := range data {
		if _, err := h.Write(p); err != nil {
			return nil, err
		}
	}
	return h, nil
}

func hash160(data []byte) []byte {
	hash1 := sha256.Sum256(data)

	h := ripemd160.New()
	h.Write(hash1[:])
	return h.Sum(nil)
}
