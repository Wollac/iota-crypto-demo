package slip10

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math/rand"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/wollac/iota-bip39-demo/bip32path"
)

type Test struct {
	Path      bip32path.BIPPath `json:"chain"`
	ChainCode hexBytes          `json:"chainCode"`
	Private   hexBytes          `json:"private"`
	Public    hexBytes          `json:"public"`
}

type TestVector struct {
	Seed  hexBytes `json:"seed"`
	Tests []Test   `json:"tests"`
}

// helper struct to read hex encoded byte slices
type hexBytes []byte

func (h hexBytes) MarshalText() ([]byte, error) {
	return []byte(hex.EncodeToString(h)), nil
}

func (h *hexBytes) UnmarshalText(text []byte) (err error) {
	*h, err = hex.DecodeString(string(text))
	return
}

func TestSecp256k1(t *testing.T) {
	tvs := readJSONTests(t)
	runCurveTests(t, Secp256k1(), tvs)
}

func TestNist256p1(t *testing.T) {
	tvs := readJSONTests(t)
	runCurveTests(t, Nist256p1(), tvs)
}

func TestEd25519(t *testing.T) {
	tvs := readJSONTests(t)
	runCurveTests(t, Ed25519(), tvs)
}

func readJSONTests(t *testing.T) []TestVector {
	b, err := ioutil.ReadFile(filepath.Join("testdata", t.Name()+".json"))
	require.NoError(t, err)

	var tvs []TestVector
	err = json.Unmarshal(b, &tvs)
	require.NoError(t, err)
	return tvs
}

func runCurveTests(t *testing.T, curve Curve, tvs []TestVector) {
	for i, tv := range tvs {
		t.Run(fmt.Sprintf("%d", i), func(t *testing.T) {
			runTests(t, tv.Seed, curve, tv.Tests)
		})
	}
}

func runTests(t *testing.T, seed []byte, curve Curve, tests []Test) {
	for _, tt := range tests {
		t.Run(strings.ReplaceAll(tt.Path.String(), "/", "|"), func(t *testing.T) {
			key, err := DeriveKeyFromPath(seed, curve, tt.Path)
			require.NoError(t, err)

			assert.EqualValues(t, tt.ChainCode, key.ChainCode, "unexpected chain code")
			assert.EqualValues(t, tt.Private, key.Key, "unexpected private key")
			assert.EqualValues(t, tt.Public, curve.PublicKey(key), "unexpected public key")
		})
	}
}

func BenchmarkDeriveKeyFromPath(b *testing.B) {
	seed := []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}
	var path []uint32
	for i := 0; i < b.N; i++ {
		path = append(path, rand.Uint32())
	}
	b.ResetTimer()

	_, _ = DeriveKeyFromPath(seed, Nist256p1(), path)
}
