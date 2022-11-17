package vrf

import (
	"bytes"
	"encoding/json"
	"math/rand"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/wollac/iota-crypto-demo/internal/hexutil"
)

var nullSeed = make([]byte, SeedSize)

func TestVerify(t *testing.T) {
	publicKey, privateKey, _ := GenerateKey(bytes.NewReader(nullSeed))

	alpha := []byte("Alice")
	piString := Prove(privateKey, alpha).Bytes()

	ok, beta := Verify(publicKey, alpha, piString)
	require.True(t, ok)
	t.Logf("beta(%d)=%x, pi(%d)=%x", len(beta), beta, len(piString), piString)

	ok, _ = Verify(publicKey, []byte("Bob"), piString)
	require.False(t, ok)
}

type testCase struct {
	SK    hexutil.Bytes `json:"sk"`
	PK    hexutil.Bytes `json:"pk"`
	Alpha hexutil.Bytes `json:"alpha"`
	PI    hexutil.Bytes `json:"pi"`
	Beta  hexutil.Bytes `json:"beta"`
}

func TestRFC(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("testdata", "rfc.json"))
	require.NoError(t, err)

	var tvs []*testCase
	require.NoError(t, json.Unmarshal(b, &tvs))

	for _, tv := range tvs {
		t.Run("", func(t *testing.T) {
			private := NewKeyFromSeed(tv.SK)

			pi := Prove(private, tv.Alpha)
			require.Equal(t, tv.PI.Bytes(), pi.Bytes())
			require.Equal(t, tv.Beta.Bytes(), pi.Hash())

			beta, err := ProofToHash(tv.PI)
			require.NoError(t, err)
			require.Equal(t, tv.Beta.Bytes(), beta)

			ok, beta := Verify(PublicKey(tv.PK), tv.Alpha, tv.PI)
			require.True(t, ok)
			require.Equal(t, tv.Beta.Bytes(), beta)
		})
	}
}

const benchAlphaLen = 8

// BenchmarkProve benchmarks the proof creation and serialization without hashing and computing beta.
func BenchmarkProve(b *testing.B) {
	_, privateKey, _ := GenerateKey(nil)
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
	publicKey, privateKey, _ := GenerateKey(nil)
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

func BenchmarkEncodeToCurve(b *testing.B) {
	encodeToCurveSalt := make([]byte, 32)
	rand.Read(encodeToCurveSalt)
	data := make([][]byte, b.N)
	for i := range data {
		data[i] = make([]byte, benchAlphaLen)
		rand.Read(data[i])
	}

	b.ResetTimer()
	for i := range data {
		_ = encodeToCurveTryAndIncrement(encodeToCurveSalt, data[i])
	}
}
