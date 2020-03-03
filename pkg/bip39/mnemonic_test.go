package bip39

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var parsePathTests = []*struct {
	s        string
	mnemonic Mnemonic
}{
	{"", Mnemonic{}},
	{" ", Mnemonic{}},
	{"abandon", Mnemonic{"abandon"}},
	{" abandon ", Mnemonic{"abandon"}},
	{" abandon  abandon", Mnemonic{"abandon", "abandon"}},
	{" abandon\u3000abandon", Mnemonic{"abandon", "abandon"}},
	{"こんにちは 世界！", Mnemonic{"こんにちは", "世界!"}},
	{"Süßölgefäß", Mnemonic{"Süßölgefäß"}},
	{"あいこくしん　あおぞら", Mnemonic{"あいこくしん", "あおぞら"}},
	{strings.Repeat("a ", 15), Mnemonic{"a", "a", "a", "a", "a", "a", "a", "a", "a", "a", "a", "a", "a", "a", "a"}},
}

func TestParseMnemonic(t *testing.T) {
	for _, tt := range parsePathTests {
		t.Run(tt.s, func(t *testing.T) {
			mnemonic := ParseMnemonic(tt.s)
			assert.Equal(t, tt.mnemonic, mnemonic)
		})
	}
}

func TestBIPPathUnmarshalText(t *testing.T) {
	for _, tt := range parsePathTests {
		t.Run(tt.s, func(t *testing.T) {
			var mnemonic Mnemonic
			err := mnemonic.UnmarshalText([]byte(tt.s))
			assert.Equal(t, tt.mnemonic, mnemonic)
			assert.NoError(t, err)
		})
	}
}

var mnemonicStringTests = []*struct {
	in  string
	out string
}{
	{"", ""},
	{" ", ""},
	{"abandon", "abandon"},
	{" abandon ", "abandon"},
	{" abandon  abandon", "abandon abandon"},
	{" abandon\u3000abandon", "abandon abandon"},
	{"こんにちは 世界！", "こんにちは 世界!"},
	{"Süßölgefäß", "Süßölgefäß"},
	{"あいこくしん　あおぞら", "あいこくしん あおぞら"},
}

func TestMnemonicString(t *testing.T) {
	for _, tt := range mnemonicStringTests {
		t.Run(tt.in, func(t *testing.T) {
			ms := ParseMnemonic(tt.in)
			assert.Equal(t, tt.out, ms.String())
		})
	}
}

func TestMnemonichMarshalText(t *testing.T) {
	for _, tt := range mnemonicStringTests {
		t.Run(tt.in, func(t *testing.T) {
			ms := ParseMnemonic(tt.in)

			b, err := ms.MarshalText()
			require.NoError(t, err)
			assert.Equal(t, []byte(tt.out), b)
		})
	}
}
