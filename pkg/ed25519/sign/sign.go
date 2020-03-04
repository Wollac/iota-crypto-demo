package sign

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"strings"

	"github.com/iotaledger/iota.go/consts"
	"github.com/iotaledger/iota.go/guards"
	"github.com/iotaledger/iota.go/kerl"
	"github.com/iotaledger/iota.go/trinary"
	"github.com/wollac/iota-bip39-demo/pkg/ed25519/address"
)

const (
	SignatureSize      = ed25519.PublicKeySize + ed25519.SignatureSize
	SignatureTryteSize = 2 * SignatureSize
)

func Generate(priv ed25519.PrivateKey, bundleHash trinary.Hash) (trinary.Trytes, error) {
	hashBytes, err := kerl.KerlTrytesToBytes(bundleHash)
	if err != nil {
		return "", err
	}

	var signatureBytes []byte
	signatureBytes = append(signatureBytes, priv.Public().(ed25519.PublicKey)...)
	signatureBytes = append(signatureBytes, ed25519.Sign(priv, hashBytes)...)

	trytes, err := bytesToTrytes(signatureBytes)
	if err != nil {
		return "", err
	}
	return trinary.Pad(trytes, consts.SignatureMessageFragmentSizeInTrytes)
}

func Verify(addressTrytes trinary.Hash, signatureFragment trinary.Trytes, bundleHash trinary.Hash) (bool, error) {
	if !guards.IsTrytesOfExactLength(signatureFragment, consts.SignatureMessageFragmentSizeInTrytes) {
		return false, errors.New("invalid signature fragment")
	}
	hashBytes, err := kerl.KerlTrytesToBytes(bundleHash)
	if err != nil {
		return false, fmt.Errorf("invalid bundle hash: %w", err)
	}

	signatureBytes, err := trytesToBytes(signatureFragment[:SignatureTryteSize])
	if err != nil {
		return false, fmt.Errorf("invalid signature fragment: %w", err)
	}

	publicKey := signatureBytes[:ed25519.PublicKeySize]
	sig := signatureBytes[ed25519.PublicKeySize:]

	expectedAddress, err := address.FromPublicKey(publicKey)
	if err != nil || expectedAddress != addressTrytes {
		return false, nil
	}

	return ed25519.Verify(publicKey, hashBytes, sig), nil
}

func bytesToTrytes(bytes []byte) (trinary.Trytes, error) {
	var trytes strings.Builder
	trytes.Grow(len(bytes) * 2)

	for _, b := range bytes {
		trytes.WriteByte(trinary.TryteValueToTyteLUT[b%27])
		trytes.WriteByte(trinary.TryteValueToTyteLUT[b/27])
	}
	return trytes.String(), nil
}

func trytesToBytes(trytes trinary.Trytes) ([]byte, error) {
	if len(trytes)%2 != 0 {
		return nil, consts.ErrInvalidOddLength
	}

	bytes := make([]byte, len(trytes)/2)
	for i := 0; i < len(trytes); i += 2 {
		v := int(trinary.TryteToTryteValueLUT[trytes[i]-'9'] - consts.MinTryteValue)
		v += 27 * int(trinary.TryteToTryteValueLUT[trytes[i+1]-'9']-consts.MinTryteValue)
		if int(byte(v)) != v {
			return nil, consts.ErrInvalidTrytes
		}
		bytes[i/2] = byte(v)
	}
	return bytes, nil
}
