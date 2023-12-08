package bip39

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/iotaledger/iota-crypto-demo/internal/hexutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type Test struct {
	Entropy    hexutil.Bytes `json:"entropy"`
	Mnemonic   Mnemonic      `json:"mnemonic"`
	Passphrase string        `json:"passphrase"`
	Seed       hexutil.Bytes `json:"seed"`
}

type TestVector struct {
	Language string `json:"language"`
	Tests    []Test `json:"tests"`
}

func TestBIP39(t *testing.T) {
	tvs := readJSONTests(t)
	for _, tv := range tvs {
		t.Run(tv.Language, func(t *testing.T) {
			require.NoError(t, SetWordList(strings.ToLower(tv.Language)))
			runTests(t, tv.Tests)
		})
	}
}

func TestEntropyToMnemonic(t *testing.T) {
	var tests = []*struct {
		entropy []byte
		expErr  error
	}{
		{
			make([]byte, 12), // too small
			ErrInvalidEntropySize,
		},
		{
			make([]byte, 68), // too big
			ErrInvalidEntropySize,
		},
		{
			make([]byte, 23), // not a multiple of 4
			ErrInvalidEntropySize,
		},
		{
			make([]byte, 25), // not a multiple of 4
			ErrInvalidEntropySize,
		},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("%v", tt.expErr), func(t *testing.T) {
			_, err := EntropyToMnemonic(tt.entropy)
			assert.Truef(t, errors.Is(err, tt.expErr), "unexpected error: %v", err)
		})
	}
}

var invalidMnemonicTests = []*struct {
	mnemonic Mnemonic
	expErr   error
}{
	{
		ParseMnemonic(strings.Repeat("abandon ", 9)), // too short
		ErrInvalidMnemonic,
	},
	{
		ParseMnemonic(strings.Repeat("abandon ", 51)), // too long
		ErrInvalidMnemonic,
	},
	{
		ParseMnemonic(strings.Repeat("abandon ", 17)), // not a multiple of 3
		ErrInvalidMnemonic,
	},
	{
		ParseMnemonic(strings.Repeat("abandon ", 19)), // not a multiple of 3
		ErrInvalidMnemonic,
	},
	{
		ParseMnemonic(strings.Repeat("brummagem ", 18)), // not in word list
		ErrInvalidMnemonic,
	},
	{
		ParseMnemonic(strings.Repeat("abandon ", 12)), // not in word list
		ErrInvalidChecksum,
	},
}

func TestMnemonicToEntropy(t *testing.T) {
	require.NoError(t, SetWordList(defaultLanguage))

	for _, tt := range invalidMnemonicTests {
		t.Run(fmt.Sprintf("%v", tt.expErr), func(t *testing.T) {
			_, err := MnemonicToEntropy(tt.mnemonic)
			assert.Truef(t, errors.Is(err, tt.expErr), "unexpected error: %v", err)
		})
	}
}

func TestMnemonicToSeed(t *testing.T) {
	require.NoError(t, SetWordList(defaultLanguage))

	for _, tt := range invalidMnemonicTests {
		t.Run(fmt.Sprintf("%v", tt.expErr), func(t *testing.T) {
			_, err := MnemonicToSeed(tt.mnemonic, "")
			assert.Truef(t, errors.Is(err, tt.expErr), "unexpected error: %v", err)
		})
	}
}

func readJSONTests(t *testing.T) []TestVector {
	b, err := os.ReadFile(filepath.Join("testdata", t.Name()+".json"))
	require.NoError(t, err)

	var tvs []TestVector
	err = json.Unmarshal(b, &tvs)
	require.NoError(t, err)
	return tvs
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

			seed, err := MnemonicToSeed(tt.Mnemonic, tt.Passphrase)
			assert.NoError(t, err)
			assert.EqualValues(t, tt.Seed, seed)
		})
	}
}
