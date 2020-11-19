package ed25519

import (
	"compress/gzip"
	"crypto/rand"
	"encoding/csv"
	"encoding/hex"
	"os"
	"path"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSignVerify(t *testing.T) {
	public, private, _ := GenerateKey(rand.Reader)

	message := []byte("test message")
	sig := Sign(private, message)
	assert.True(t, Verify(public, message, sig), "valid signature rejected")

	wrongMessage := []byte("wrong message")
	assert.False(t, Verify(public, wrongMessage, sig), "signature of different message accepted")
}

func TestEqual(t *testing.T) {
	public, private, _ := GenerateKey(rand.Reader)
	assert.Equalf(t, public, private.Public(), " private.Public() is not Equal to public")

	otherPub, otherPriv, _ := GenerateKey(rand.Reader)
	assert.NotEqual(t, public, otherPub)
	assert.NotEqual(t, private, otherPriv)
}

func TestGolden(t *testing.T) {
	// sign.input.gz is a selection of test tests from https://ed25519.cr.yp.to/python/sign.input
	file, err := os.Open(path.Join("testdata", "sign.input.gz"))
	require.NoError(t, err)
	defer file.Close()

	testData, err := gzip.NewReader(file)
	require.NoError(t, err)
	defer testData.Close()

	// parse the test data as colon separated values
	r := csv.NewReader(testData)
	r.Comma = ':'

	records, err := r.ReadAll()
	require.NoError(t, err)

	// fields on each input line: sk, pk, m, sm
	for _, record := range records {
		sk, _ := hex.DecodeString(record[0])
		pk, _ := hex.DecodeString(record[1])
		m, _ := hex.DecodeString(record[2])
		sm, _ := hex.DecodeString(record[3])
		s := sm[:SignatureSize]

		privateKey := NewKeyFromSeed(sk[:SeedSize])
		assert.EqualValues(t, sk, privateKey, "different private key")
		assert.EqualValues(t, sk[:SeedSize], privateKey.Seed(), "different seed")

		publicKey := privateKey.Public().(PublicKey)
		assert.EqualValues(t, pk, publicKey, "different public key")

		sig := Sign(privateKey, m)
		assert.Equal(t, s, sig, "different signature")
		assert.True(t, Verify(publicKey, m, sig), "invalid signature")
	}
}
