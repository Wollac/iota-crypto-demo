package migration

import (
	"bytes"
	"fmt"
	"strings"

	"github.com/iotaledger/iota.go/consts"
	"github.com/iotaledger/iota.go/encoding/b1t6"
	"github.com/iotaledger/iota.go/guards"
	"github.com/iotaledger/iota.go/trinary"
	"golang.org/x/crypto/blake2b"
)

const (
	Ed25519AddressSize = blake2b.Size256
	ChecksumSize       = 4
	Prefix             = trinary.Trytes("TRANSFER")
	Suffix             = "9"
)

func Encode(addr [Ed25519AddressSize]byte) trinary.Trytes {
	hash := blake2b.Sum256(addr[:])
	return Prefix + b1t6.EncodeToTrytes(append(addr[:], hash[:ChecksumSize]...)) + Suffix
}

func Decode(trytes trinary.Hash) (addr [Ed25519AddressSize]byte, err error) {
	if !guards.IsTrytesOfExactLength(trytes, consts.HashTrytesSize) {
		return addr, consts.ErrInvalidTrytesLength
	}
	if !strings.HasPrefix(trytes, Prefix) {
		return addr, fmt.Errorf("expected prefix '%s'", Prefix)
	}
	trytes = strings.TrimPrefix(trytes, Prefix)
	if !strings.HasSuffix(trytes, Suffix) {
		return addr, fmt.Errorf("expected suffix '%s'", Suffix)
	}
	trytes = strings.TrimSuffix(trytes, Suffix)

	addrTrytesLen := b1t6.EncodedLen(Ed25519AddressSize) / consts.TritsPerTryte
	addrBytes, err := b1t6.DecodeTrytes(trytes[:addrTrytesLen])
	if err != nil {
		return addr, fmt.Errorf("invalid address encoding: %w", err)
	}
	checksumBytes, err := b1t6.DecodeTrytes(trytes[addrTrytesLen:])
	if err != nil {
		return addr, fmt.Errorf("invalid checksum encoding: %w", err)
	}
	hash := blake2b.Sum256(addrBytes)
	if !bytes.Equal(checksumBytes, hash[:len(checksumBytes)]) {
		return addr, consts.ErrInvalidChecksum
	}
	copy(addr[:], addrBytes)
	return addr, nil
}
