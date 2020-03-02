package bip39

import (
	"encoding/json"
	"io/ioutil"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/wollac/iota-bip39-demo/bip39/wordlists"
	"github.com/wollac/iota-bip39-demo/testutil"
)

type Test struct {
	Entropy    testutil.HexBytes `json:"entropy"`
	Mnemonic   Mnemonic          `json:"mnemonic"`
	Passphrase string            `json:"passphrase"`
	Seed       testutil.HexBytes `json:"seed"`
}

type TestVector struct {
	Language string `json:"language"`
	Tests    []Test `json:"tests"`
}

func TestBIP39(t *testing.T) {
	tvs := readJSONTests(t)
	for _, tv := range tvs {
		t.Run(tv.Language, func(t *testing.T) {
			setLanguage(t, tv.Language)
			runTests(t, tv.Tests)
		})
	}
}

func readJSONTests(t *testing.T) []TestVector {
	b, err := ioutil.ReadFile(filepath.Join("testdata", t.Name()+".json"))
	require.NoError(t, err)

	var tvs []TestVector
	err = json.Unmarshal(b, &tvs)
	require.NoError(t, err)
	return tvs
}

func setLanguage(t *testing.T, language string) {
	switch strings.ToLower(language) {
	case "english":
		SetWordList(wordlists.English)
	case "japanese":
		SetWordList(wordlists.Japanese)
	default:
		t.Fatalf("unexpected language: %s", language)
	}
}

func runTests(t *testing.T, tests []Test) {
	for _, tt := range tests {
		t.Run("", func(t *testing.T) {
			ms, err := EntropyToMnemonic(tt.Entropy)
			assert.NoError(t, err)
			assert.Equal(t, tt.Mnemonic, ms)

			ent, err := MnemonicToEntropy(tt.Mnemonic)
			assert.NoError(t, err)
			assert.EqualValues(t, tt.Entropy, ent)

			seed := MnemonicToSeed(tt.Mnemonic, tt.Passphrase)
			assert.EqualValues(t, tt.Seed, seed)
		})
	}
}
