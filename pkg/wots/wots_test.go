package wots

import (
	"math/rand"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestVerify(t *testing.T) {
	message := []byte("hello, world!")

	key, err := GenerateKey(nil)
	require.NoError(t, err)
	assert.Len(t, key, PrivateKeySize)

	nonce, signature := Sign(key, 0, message)
	assert.Len(t, signature, SignatureSize)
	t.Log(nonce, signature)

	pub := key.Public()
	assert.Len(t, pub, PublicKeySize)
	valid := Verify(pub, 0, message, nonce, signature)
	assert.True(t, valid)

	// create an invalid signature
	invalidSig := append([]byte{}, signature...)
	invalidSig[0]++

	invalid := Verify(pub, 0, message, nonce, invalidSig)
	assert.False(t, invalid)
}

func BenchmarkVerify(b *testing.B) {
	type foo struct {
		message   []byte
		nonce     uint64
		signature []byte
	}
	key, _ := GenerateKey(nil)
	pub := key.Public()
	data := make([]foo, b.N)
	for i := range data {
		message := make([]byte, 300)
		rand.Read(message)
		data[i].nonce, data[i].signature = Sign(key, 0, message)
		data[i].message = message
	}
	b.ResetTimer()

	for i := range data {
		_ = Verify(pub, 0, data[i].message, data[i].nonce, data[i].signature)
	}
}
