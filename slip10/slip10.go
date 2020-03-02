package slip10

import (
	"crypto/hmac"
	"crypto/sha512"
	"encoding/binary"
	"fmt"
)

const (
	// PrivateKeySize is the size, in bytes, of the normal private key.
	PrivateKeySize = 32
	// PublicKeySize is the size, in bytes, of the normal public key.
	PublicKeySize = 33
	// ChainCodeSize is the size, in bytes, of the chain code.
	ChainCodeSize = 32

	hardened uint32 = 1 << 31
)

// Key represents a SLIP-10 extended private key.
type Key struct {
	Key       []byte
	ChainCode []byte
	curve     Curve
}

// DeriveKeyFromPath derives an extended private key for the curve from seed and path as outlined by SLIP-10.
func DeriveKeyFromPath(seed []byte, curve Curve, path []uint32) (*Key, error) {
	key, err := NewMasterKey(seed, curve)
	if err != nil {
		return nil, err
	}
	for _, childIndex := range path {
		key, err = key.NewChildKey(childIndex)
		if err != nil {
			return nil, err
		}
	}
	return key, nil
}

// NewMasterKey creates a new master private extended key for the curve from a seed.
func NewMasterKey(seed []byte, curve Curve) (*Key, error) {
	// Calculate I = HMAC-SHA512(Key = Curve, Data = seed)
	inter, err := hmacSHA256(curve.SeedKey(), seed)
	if err != nil {
		return nil, err
	}

	// Split I into two 32-byte sequences, I_L and I_R
	// Use parse256(I_L) as secret key, and I_R as chain code.
	secretKey := inter[:32]
	chainCode := inter[32:]

	key := &Key{
		ChainCode: chainCode,
		Key:       secretKey,
		curve:     curve,
	}
	return key, nil
}

// NewChildKey derives a child extended private key from a given parent extended private key as outlined by SLIP-10.
func (key *Key) NewChildKey(index uint32) (*Key, error) {
	if err := key.curve.ValidateChildIndex(index); err != nil {
		return nil, fmt.Errorf("invalid child index (%d): %w", index, err)
	}

	inter, err := key.getIntermediary(index)
	if err != nil {
		return nil, err
	}

	// Split I into two 32-byte sequences, I_L and I_R
	left := inter[:32]
	right := inter[32:]

	// The returned chain code c_i is I_R.
	chainCode := right

	// Compute the private key from I_L and k_par
	privateKey, err := key.curve.PrivateKey(left, key.Key)
	if err != nil {
		return nil, err
	}

	childKey := &Key{
		ChainCode: chainCode,
		Key:       privateKey,
		curve:     key.curve,
	}
	return childKey, nil
}

func (key *Key) getIntermediary(childIndex uint32) ([]byte, error) {
	var data []byte
	if childIndex >= hardened {
		data = append([]byte{0x0}, key.Key...)
	} else {
		data = key.curve.PublicKey(key)
	}
	data = append(data, uint32Bytes(childIndex)...)

	return hmacSHA256(key.ChainCode, data)
}

func hmacSHA256(key []byte, data []byte) ([]byte, error) {
	hash := hmac.New(sha512.New, key)
	_, err := hash.Write(data)
	if err != nil {
		return nil, err
	}
	return hash.Sum(nil), nil
}

func uint32Bytes(i uint32) []byte {
	bytes := make([]byte, 4)
	binary.BigEndian.PutUint32(bytes, i)
	return bytes
}
