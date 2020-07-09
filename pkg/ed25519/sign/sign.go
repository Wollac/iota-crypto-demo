package sign

import (
	"crypto/ed25519"
	"fmt"
	"strings"

	"github.com/iotaledger/iota.go/consts"
	"github.com/iotaledger/iota.go/guards"
	"github.com/iotaledger/iota.go/kerl"
	"github.com/iotaledger/iota.go/trinary"
	"github.com/wollac/iota-bip39-demo/pkg/ed25519/address"
	"github.com/wollac/iota-bip39-demo/pkg/encoding/b1t6"
)

const (
	// SignatureSize is the size, in bytes, of signatures generated and verified by this package.
	SignatureSize = ed25519.PublicKeySize + ed25519.SignatureSize
	// SignatureTryteSize is the size of a signature converted to trytes.
	SignatureTryteSize = SignatureSize * 2
)

// Sign signs bundleHash with privateKey and returns a signature.
func Sign(privateKey ed25519.PrivateKey, bundleHash trinary.Hash) (trinary.Trytes, error) {
	if err := validHash(bundleHash); err != nil {
		return "", fmt.Errorf("invalid bundle hash: %w", err)
	}
	hashBytes, err := kerl.KerlTrytesToBytes(bundleHash)
	if err != nil {
		return "", fmt.Errorf("invalid bundle hash: %w", err)
	}

	signatureBytes := make([]byte, SignatureSize)
	copy(signatureBytes, privateKey.Public().(ed25519.PublicKey))
	copy(signatureBytes[ed25519.PublicKeySize:], ed25519.Sign(privateKey, hashBytes))

	signatureTrytes := b1t6.EncodeToTrytes(signatureBytes)
	return trinary.Pad(signatureTrytes, consts.SignatureMessageFragmentSizeInTrytes)
}

// Verify reports whether signatureFragment is a valid signature of bundleHash and belongs to addressTrytes.
func Verify(addressTrytes trinary.Hash, signatureFragment trinary.Trytes, bundleHash trinary.Hash) (bool, error) {
	if !guards.IsTrytesOfExactLength(signatureFragment, consts.SignatureMessageFragmentSizeInTrytes) {
		return false, fmt.Errorf("invalid signature fragment: %w", consts.ErrInvalidTrytes)
	}
	// longer signatures must be rejected to prevent signature malleability
	if len(strings.TrimRight(signatureFragment, "9")) > SignatureTryteSize {
		return false, nil
	}

	signatureBytes, err := b1t6.DecodeTrytes(signatureFragment[:SignatureTryteSize])
	if err != nil {
		return false, fmt.Errorf("invalid signature fragment: %w", err)
	}
	hashBytes, err := kerl.KerlTrytesToBytes(bundleHash)
	if err != nil {
		return false, fmt.Errorf("invalid bundle hash: %w", err)
	}

	publicKey := signatureBytes[:ed25519.PublicKeySize]
	sig := signatureBytes[ed25519.PublicKeySize:]
	expectedAddress, err := address.FromPublicKey(publicKey)
	if err != nil || expectedAddress != addressTrytes {
		return false, nil
	}
	return ed25519.Verify(publicKey, hashBytes, sig), nil
}

func validHash(hash trinary.Hash) error {
	if len(hash) != consts.HashTrytesSize {
		return consts.ErrInvalidTrytesLength
	}
	if err := trinary.ValidTrytes(hash); err != nil {
		return err
	}
	// a valid hash must have the last trit set to zero
	lastTrits := trinary.MustTrytesToTrits(string(hash[consts.HashTrytesSize-1]))
	if lastTrits[consts.TritsPerTryte-1] != 0 {
		return consts.ErrInvalidHash
	}
	return nil
}
