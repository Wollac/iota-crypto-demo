package wots

import (
	"crypto/rand"
	"testing"

	"github.com/iotaledger/iota.go/consts"
	"github.com/iotaledger/iota.go/trinary"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	seed                               = "ZLNM9UHJWKTTDEZOTH9CXDEIFUJQCIACDPJIXPOWBDW9LTBHC9AQRIXTIHYLIIURLZCXNSTGNIVC9ISVB"
	securityLevel consts.SecurityLevel = 3
)

func TestVerify(t *testing.T) {
	priv, err := GenerateKey(trinary.MustTrytesToTrits(seed), securityLevel)
	require.NoError(t, err)
	assert.Len(t, priv, int(securityLevel)*consts.KeyFragmentLength)

	message := []byte("testing")
	nonce, sig, err := Sign(rand.Reader, priv, message)
	require.NoError(t, err)
	assert.Len(t, nonce, NonceSize)
	assert.Len(t, sig, int(securityLevel)*consts.KeyFragmentLength)
	t.Logf("nonce:%x signature:%v", nonce, sig)

	address := priv.Address()
	assert.Len(t, address, consts.HashTrinarySize)

	valid := Verify(address, message, nonce, sig)
	assert.True(t, valid)

	// create invalid signatures
	invalidSig := append(trinary.Trits{}, sig...)
	if invalidSig[0] < 1 {
		invalidSig[0] = 1
	} else {
		invalidSig[0] = -1
	}
	assert.False(t, Verify(address, message, nonce, invalidSig))
}

func TestSignatureEncoding(t *testing.T) {
	priv, err := GenerateKey(trinary.MustTrytesToTrits(seed), securityLevel)
	require.NoError(t, err)

	message := []byte("testing")
	_, sig, err := Sign(rand.Reader, priv, message)
	require.NoError(t, err)

	data, err := sig.MarshalBinary()
	require.NoError(t, err)

	sig2 := Signature{}
	err = sig2.UnmarshalBinary(data)
	require.NoError(t, err)

	assert.Equal(t, sig, sig2)
}

func BenchmarkVerify(b *testing.B) {
	type datum struct {
		message   []byte
		nonce     [NonceSize]byte
		signature Signature
	}
	priv, _ := GenerateKey(trinary.MustTrytesToTrits(seed), 2)
	data := make([]datum, b.N)
	for i := range data {
		message := make([]byte, 1600)
		rand.Read(message)
		data[i].nonce, data[i].signature, _ = Sign(rand.Reader, priv, message)
		data[i].message = message
	}
	address := priv.Address()
	b.ResetTimer()

	for i := range data {
		_ = Verify(address, data[i].message, data[i].nonce, data[i].signature)
	}
}
