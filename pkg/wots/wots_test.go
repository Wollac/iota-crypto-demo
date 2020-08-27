package wots

import (
	"crypto/rand"
	"testing"

	"github.com/iotaledger/iota.go/consts"
	"github.com/iotaledger/iota.go/signing"
	"github.com/iotaledger/iota.go/signing/key"
	"github.com/iotaledger/iota.go/trinary"
	"github.com/stretchr/testify/assert"
	"github.com/wollac/iota-crypto-demo/pkg/encoding/t5b1"
)

const (
	seed          = "ZLNM9UHJWKTTDEZOTH9CXDEIFUJQCIACDPJIXPOWBDW9LTBHC9AQRIXTIHYLIIURLZCXNSTGNIVC9ISVB"
	securityLevel = 3
)

func TestVerify(t *testing.T) {
	priv, address := generateKey(seed, securityLevel)
	assert.Len(t, priv, securityLevel*consts.KeyFragmentLength)
	assert.Len(t, address, consts.HashTrinarySize)

	message := []byte("testing")
	nonce, sig, err := Sign(rand.Reader, priv, message)
	assert.Len(t, nonce, NonceSize)
	assert.Len(t, sig, t5b1.EncodedLen(securityLevel*consts.SignatureMessageFragmentTrinarySize))
	assert.NoError(t, err)

	valid := Verify(address, message, nonce, sig)
	assert.True(t, valid)

	// create an invalid signatures
	invalidSig := append([]byte{}, sig...)
	invalidSig[0] = sig[0] + 1
	assert.False(t, Verify(address, message, nonce, invalidSig))
	invalidSig[0] = sig[0] - 1
	assert.False(t, Verify(address, message, nonce, invalidSig))
}

func BenchmarkVerify(b *testing.B) {
	type datum struct {
		nonce     [NonceSize]byte
		message   []byte
		signature []byte
	}
	private, public := generateKey(seed, 2)
	data := make([]datum, b.N)
	for i := range data {
		message := make([]byte, 300)
		rand.Read(message)
		data[i].nonce, data[i].signature, _ = Sign(rand.Reader, private, message)
		data[i].message = message
	}
	b.ResetTimer()

	for i := range data {
		_ = Verify(public, data[i].message, data[i].nonce, data[i].signature)
	}
}

func generateKey(seed trinary.Trytes, securityLevel int) (trinary.Trits, trinary.Trits) {
	entropy, err := trinary.TrytesToTrits(seed)
	if err != nil {
		panic(err)
	}
	private, err := key.Shake(entropy, consts.SecurityLevel(securityLevel))
	if err != nil {
		panic(err)
	}
	digests, err := signing.Digests(append(trinary.Trits{}, private...))
	if err != nil {
		panic(err)
	}
	public, _ := signing.Address(digests)
	return private, public
}
