package bip39

import (
	"fmt"
	"math/big"
)

const (
	entropyMultiple = 32
	entropyMinBits  = 128
	entropyMaxBits  = 512

	wordIndexBits = 11
)

// bit mask for 11 least significant bits
var wordIndexMask = big.NewInt(1<<wordIndexBits - 1)
var bigOne = big.NewInt(1)

func entToMS(ent int) int {
	return 3 * ent / 32
}

func msToEnt(ms int) int {
	return 32 * ms / 3
}

// check that the number of bits is within max, min and a multiple of 32
func validateEntropy(entropy []byte) error {
	ent := len(entropy) * 8
	if ent%entropyMultiple != 0 || entropyMinBits > ent || ent > entropyMaxBits {
		return fmt.Errorf("%w: unsupported bit size (%d)", ErrInvalidEntropySize, ent)
	}
	return nil
}

func validateMnemonic(mnemonic Mnemonic) error {
	ms := len(mnemonic)
	if ms%3 != 0 || entToMS(entropyMinBits) > ms || ms > entToMS(entropyMaxBits) {
		return fmt.Errorf("%w: unsupported word count (%d)", ErrInvalidMnemonic, ms)
	}

	for _, word := range mnemonic {
		if !wordList.Contains(word) {
			return fmt.Errorf("%w: invalid word (%s)", ErrInvalidMnemonic, word)
		}
	}
	return nil
}

func padBytes(b []byte, size int) []byte {
	l := len(b)
	if l > size {
		panic(fmt.Sprintf("invalid size: %d", l))
	}
	// append zeros to match the requested size
	return append(b, make([]byte, size-l)...)
}
