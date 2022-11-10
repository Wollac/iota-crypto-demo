package bls

import (
	"math/rand"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestVerify(t *testing.T) {
	publicKey, privateKey := GenerateKey()

	alpha := []byte("Alice")
	piString := Prove(privateKey, alpha)

	ok, beta := Verify(publicKey, alpha, piString)
	require.True(t, ok)
	t.Logf("beta(%d)=%x, pi(%d)=%x", len(beta), beta, len(piString), piString)

	ok, _ = Verify(publicKey, []byte("Bob"), piString)
	require.False(t, ok)
}

const benchAlphaLen = 8

// BenchmarkProve benchmarks the proof creation and serialization without hashing and computing beta.
func BenchmarkProve(b *testing.B) {
	_, privateKey := GenerateKey()
	data := make([][benchAlphaLen]byte, b.N)
	for i := range data {
		rand.Read(data[i][:])
	}

	b.ResetTimer()
	for i := range data {
		_ = Prove(privateKey, data[i][:]).Bytes()
	}
}

// BenchmarkVerify benchmarks the proof verification including hashing and computing beta.
func BenchmarkVerify(b *testing.B) {
	publicKey, privateKey := GenerateKey()
	data := make([]struct {
		alpha []byte
		pi    []byte
	}, b.N)
	for i := range data {
		data[i].alpha = make([]byte, benchAlphaLen)
		rand.Read(data[i].alpha)
		data[i].pi = Prove(privateKey, data[i].alpha).Bytes()
	}

	b.ResetTimer()
	for i := range data {
		_, _ = Verify(publicKey, data[i].alpha, data[i].pi)
	}
}
