package address

import (
	"crypto/ed25519"
	"fmt"

	"github.com/iotaledger/iota.go/checksum"
	"github.com/iotaledger/iota.go/consts"
	"github.com/iotaledger/iota.go/kerl"
	"github.com/iotaledger/iota.go/kerl/sha3"
	"github.com/iotaledger/iota.go/trinary"
)

// Generate returns the IOTA address corresponding to the public key contained in the given keyPair.
// If addChecksum is true, the 9 tryte checksum is added to the address.
func Generate(keyPair ed25519.PrivateKey, addChecksum ...bool) (trinary.Trytes, error) {
	if l := len(keyPair); l != ed25519.PrivateKeySize {
		return "", fmt.Errorf("%w: invalid key length %d", consts.ErrInvalidBytesLength, l)
	}
	publicKey := keyPair.Public().(ed25519.PublicKey)
	return FromPublicKey(publicKey, addChecksum...)
}

// FromPublicKey returns the IOTA address corresponding to publicKey.
// If addChecksum is true, the 9 tryte checksum is added to the address.
func FromPublicKey(publicKey ed25519.PublicKey, addChecksum ...bool) (trinary.Trytes, error) {
	if l := len(publicKey); l != ed25519.PublicKeySize {
		return "", fmt.Errorf("%w: invalid key length %d", consts.ErrInvalidBytesLength, l)
	}
	addressBytes := sumLegacyKeccak384(publicKey)
	addressTrytes, err := kerl.KerlBytesToTrytes(addressBytes)
	if err != nil {
		return "", err
	}

	if len(addChecksum) > 0 && addChecksum[0] {
		return checksum.AddChecksum(addressTrytes, true, consts.AddressChecksumTrytesSize)
	}
	return addressTrytes, nil
}

func sumLegacyKeccak384(data []byte) []byte {
	h := sha3.New384()
	h.Write(data)
	return h.Sum(nil)
}
