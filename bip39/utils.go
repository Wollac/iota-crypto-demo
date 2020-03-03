package bip39

import (
	"fmt"
	"math/big"

	"github.com/wollac/iota-bip39-demo/bip39/wordlists"
)

const (
	entropyMultiple = 32
	entropyMinBits  = 128
	entropyMaxBits  = 512
)

// bit mask for the 11 least significant bits
var wordIndexMask = big.NewInt(1<<wordlists.IndexBits - 1)
var bigOne = big.NewInt(1)

func entropyBitsToWordCount(n int) int {
	return 3 * n / 32
}

func wordCountToEntropyBits(n int) int {
	return 32 * n / 3
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
	if ms%3 != 0 || entropyBitsToWordCount(entropyMinBits) > ms || ms > entropyBitsToWordCount(entropyMaxBits) {
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
		panic("invalid byte size")
	}
	// append zeros to match the requested size
	return append(b, make([]byte, size-l)...)
}
