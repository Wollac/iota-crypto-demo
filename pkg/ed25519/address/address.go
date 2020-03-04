package address

import (
	"crypto/ed25519"

	"github.com/iotaledger/iota.go/checksum"
	"github.com/iotaledger/iota.go/consts"
	"github.com/iotaledger/iota.go/kerl"
	"github.com/iotaledger/iota.go/kerl/sha3"
	"github.com/iotaledger/iota.go/trinary"
)

func Generate(keyPair ed25519.PrivateKey, addChecksum ...bool) (trinary.Trytes, error) {
	publicKey := keyPair.Public().(ed25519.PublicKey)
	return FromPublicKey(publicKey, addChecksum...)
}

func FromPublicKey(publicKey ed25519.PublicKey, addChecksum ...bool) (trinary.Trytes, error) {
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
