package slip10_test

import (
	"crypto/ecdsa"
	cryptorand "crypto/rand"
	"encoding/hex"
	"encoding/json"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/iotaledger/iota-crypto-demo/internal/hexutil"
	"github.com/iotaledger/iota-crypto-demo/pkg/bip32path"
	"github.com/iotaledger/iota-crypto-demo/pkg/ed25519"
	"github.com/iotaledger/iota-crypto-demo/pkg/slip10"
	"github.com/iotaledger/iota-crypto-demo/pkg/slip10/eddsa"
	"github.com/iotaledger/iota-crypto-demo/pkg/slip10/elliptic"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type Test struct {
	Path        bip32path.Path `json:"chain"`
	Fingerprint hexutil.Bytes  `json:"fingerprint"`
	ChainCode   hexutil.Bytes  `json:"chainCode"`
	Private     hexutil.Bytes  `json:"private"`
	Public      hexutil.Bytes  `json:"public"`
}

type TestVector struct {
	Seed  hexutil.Bytes `json:"seed"`
	Tests []Test        `json:"tests"`
}

func TestSecp256k1(t *testing.T) {
	tvs := readJSONTests(t)
	runCurveTests(t, elliptic.Secp256k1(), tvs)
}

func TestNist256p1(t *testing.T) {
	tvs := readJSONTests(t)
	runCurveTests(t, elliptic.Nist256p1(), tvs)
}

func TestEd25519(t *testing.T) {
	tvs := readJSONTests(t)
	runCurveTests(t, eddsa.Ed25519(), tvs)
}

func TestNist256p1Retry(t *testing.T) {
	tvs := readJSONTests(t)
	runCurveTests(t, elliptic.Nist256p1(), tvs)
}

func TestECDSAKey(t *testing.T) {
	seed, _ := hex.DecodeString("000102030405060708090a0b0c0d0e0f")
	parentKey, err := slip10.DeriveKeyFromPath(seed, elliptic.Nist256p1(), []uint32{0 | slip10.Hardened})
	require.NoError(t, err)

	hashed := []byte("testing")
	for index := uint32(0); index < 100; index++ {
		privateKey, err := parentKey.DeriveChild(index)
		require.NoError(t, err)
		require.True(t, privateKey.IsPrivate())
		publicKey, err := parentKey.Public().DeriveChild(index)
		require.NoError(t, err)
		require.False(t, publicKey.IsPrivate())

		// sign with the private extended key
		priv := privateKey.Key.(*elliptic.PrivateKey).ECDSAPrivateKey()
		r, s, err := ecdsa.Sign(cryptorand.Reader, priv, hashed)
		require.NoErrorf(t, err, "sign failed")

		// verify with the public extended key
		pub := publicKey.Key.(*elliptic.PublicKey).ECDSAPublicKey()
		require.Equal(t, priv.PublicKey, *pub)
		require.Truef(t, ecdsa.Verify(pub, hashed, r, s), "verify failed")
	}
}

func TestEd25519Key(t *testing.T) {
	seed, _ := hex.DecodeString("000102030405060708090a0b0c0d0e0f")
	parentKey, err := slip10.DeriveKeyFromPath(seed, eddsa.Ed25519(), []uint32{0 | slip10.Hardened})
	require.NoError(t, err)

	message := []byte("test message")
	for index := uint32(0); index < 100; index++ {
		privateKey, err := parentKey.DeriveChild(index | slip10.Hardened)
		require.NoError(t, err)

		pub, priv := privateKey.Key.(eddsa.Seed).Ed25519Key()
		sig := ed25519.Sign(priv, message)
		require.Truef(t, ed25519.Verify(pub, message, sig), "verify failed")
	}
}

func TestEd25519PublicDerivation(t *testing.T) {
	seed, _ := hex.DecodeString("000102030405060708090a0b0c0d0e0f")
	parentKey, err := slip10.DeriveKeyFromPath(seed, eddsa.Ed25519(), []uint32{0 | slip10.Hardened})
	require.NoError(t, err)

	_, err = parentKey.Public().DeriveChild(0)
	require.ErrorIs(t, err, eddsa.ErrNotHardened)
}

func readJSONTests(t *testing.T) []TestVector {
	b, err := os.ReadFile(filepath.Join("testdata", t.Name()+".json"))
	require.NoError(t, err)

	var tvs []TestVector
	err = json.Unmarshal(b, &tvs)
	require.NoError(t, err)
	return tvs
}

func runCurveTests(t *testing.T, curve slip10.Curve, tvs []TestVector) {
	for _, tv := range tvs {
		t.Run("", func(t *testing.T) {
			runTests(t, tv.Seed, curve, tv.Tests)
		})
	}
}

func runTests(t *testing.T, seed []byte, curve slip10.Curve, tests []Test) {
	for _, tt := range tests {
		t.Run(strings.ReplaceAll(tt.Path.String(), "/", "|"), func(t *testing.T) {
			privateKey, err := slip10.DeriveKeyFromPath(seed, curve, tt.Path)
			require.NoError(t, err)

			assert.EqualValues(t, tt.Fingerprint, privateKey.Fingerprint(), "unexpected fingerprint")
			assert.EqualValues(t, tt.ChainCode, privateKey.ChainCode, "unexpected chain code")
			assert.EqualValues(t, tt.Private, privateKey.Key.Bytes(), "unexpected private key")
			assert.EqualValues(t, tt.Public, privateKey.Key.Public().Bytes(), "unexpected public key")
			assert.True(t, privateKey.IsPrivate())

			// if the path is hardened, just check the corresponding public key
			if len(tt.Path) == 0 || tt.Path[len(tt.Path)-1] >= slip10.Hardened {
				publicKey := privateKey.Public()
				assert.EqualValues(t, tt.Fingerprint, publicKey.Fingerprint(), "unexpected fingerprint")
				assert.EqualValues(t, tt.ChainCode, publicKey.ChainCode, "unexpected chain code")
				assert.EqualValues(t, tt.Public, publicKey.Key.Bytes(), "unexpected public key")
				assert.False(t, publicKey.IsPrivate())

				return
			}

			// otherwise also test

			// first, derive the second last public key
			// then, derive the final public key from that public key
			key, err := slip10.DeriveKeyFromPath(seed, curve, tt.Path[:len(tt.Path)-1])
			require.NoError(t, err)

			publicKey, err := key.Public().DeriveChild(tt.Path[len(tt.Path)-1])
			require.NoError(t, err)

			assert.EqualValues(t, tt.Fingerprint, publicKey.Fingerprint(), "unexpected fingerprint")
			assert.EqualValues(t, tt.ChainCode, publicKey.ChainCode, "unexpected chain code")
			assert.EqualValues(t, tt.Public, publicKey.Key.Bytes(), "unexpected public key")
			assert.False(t, publicKey.IsPrivate())
		})
	}
}

func BenchmarkHardenedDerivation(b *testing.B) {
	seed, _ := hex.DecodeString("000102030405060708090a0b0c0d0e0f")
	key, err := slip10.NewMasterKey(seed, elliptic.Nist256p1())
	require.NoError(b, err)

	var path []uint32
	for i := 0; i < b.N; i++ {
		path = append(path, rand.Uint32()|slip10.Hardened)
	}
	b.ResetTimer()

	for _, index := range path {
		key, _ = key.DeriveChild(index)
	}
}
