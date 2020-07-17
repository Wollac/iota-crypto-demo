package sign

import (
	"crypto/ed25519"
	"errors"
	"strings"
	"testing"

	"github.com/iotaledger/iota.go/consts"
	"github.com/iotaledger/iota.go/trinary"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/wollac/iota-crypto-demo/pkg/ed25519/address"
	"github.com/wollac/iota-crypto-demo/pkg/encoding/b1t6"
)

func TestSignVerify(t *testing.T) {
	key := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	adr, _ := address.Generate(key)
	bundleHash := consts.NullHashTrytes

	sig, err := Sign(key, bundleHash)
	require.NoError(t, err)

	verified, err := Verify(adr, sig, bundleHash)
	require.NoError(t, err)
	assert.True(t, verified)

	wrongBundleHash := "N" + bundleHash[1:]
	verified, err = Verify(adr, sig, wrongBundleHash)
	require.NoError(t, err)
	assert.False(t, verified)
}

func TestSign(t *testing.T) {
	var tests = []*struct {
		bundleHash trinary.Hash
		expErr     error
	}{
		{"", consts.ErrInvalidTrytesLength},
		{strings.Repeat("9", consts.HashTrytesSize-1), consts.ErrInvalidTrytesLength},
		{strings.Repeat("9", consts.HashTrytesSize+1), consts.ErrInvalidTrytesLength},
		{strings.Repeat("1", consts.HashTrytesSize), consts.ErrInvalidTrytes},
		{strings.Repeat("M", consts.HashTrytesSize), consts.ErrInvalidHash},
		{"MHGMDDOYZHYGHKAXMRWVZHFAMWWNFIYRZCXLNH9MFIKEQABOBPJRCILXPTFHI9OTBGQKPURLN9YHGTLN9", nil},
		{"EASU9IWDCKMVJVQCKQVHLYCODGWK9QUKCEDJDHFZCPIHXIIVYOEBMMVWIFPFOEMWKPSRSYQJVXZBVFCJC", nil},
		{"BN9DRUPBWLXEGAIAHGFVWHKSPLYXCIJDLQTVGNWUATTXKFAM9MPOFTWCNIOIIMLKUKAKKWNP9JKSLYHOC", nil},
		{"XJDFHQ9EOEAGVMCBGIJROKKIJNHYBRCEFJWSCGUYKCUZRQENUOTHOETPYWOJSTAHPU9WXZSDNJQJEKTFC", nil},
		{"PMEZUWOZOSYMHDTOJXJ9QRJXZPSLAVCOJRNFNKPZSVC9RVNVURHNGVBIJPOXWGCLQQBO9ASVKMEOCNSTX", nil},
	}

	key := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	adr, _ := address.Generate(key)
	for _, tt := range tests {
		t.Run(tt.bundleHash, func(t *testing.T) {
			sig, err := Sign(key, tt.bundleHash)
			require.Truef(t, errors.Is(err, tt.expErr), "unexpected error: %v", err)
			if tt.expErr == nil {
				verified, err := Verify(adr, sig, tt.bundleHash)
				require.NoError(t, err)
				assert.True(t, verified)
			}
		})
	}
}

func TestVerify(t *testing.T) {
	key := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	adr, _ := address.Generate(key)
	nullSigTrytes, _ := Sign(key, consts.NullHashTrytes)
	nullSigTrytes = nullSigTrytes[:SignatureTryteSize]

	var tests = []*struct {
		signatureFragment trinary.Trytes
		bundleHash        trinary.Hash
		expErr            error
		expVerified       bool
	}{
		{"", consts.NullHashTrytes, consts.ErrInvalidTrytes, false},
		// {consts.NullSignatureMessageFragmentTrytes, "", consts.ErrInvalidTrytesLength, false},
		{consts.NullSignatureMessageFragmentTrytes, consts.NullHashTrytes, nil, false},
		{trinary.MustPad("TE", consts.SignatureMessageFragmentSizeInTrytes), consts.NullHashTrytes, b1t6.ErrInvalidTrits, false},
		{trinary.MustPad(nullSigTrytes+"AA", consts.SignatureMessageFragmentSizeInTrytes), consts.NullHashTrytes, nil, false},
		{trinary.MustPad(nullSigTrytes, consts.SignatureMessageFragmentSizeInTrytes), consts.NullHashTrytes, nil, true},
	}

	for _, tt := range tests {
		t.Run("", func(t *testing.T) {
			verified, err := Verify(adr, tt.signatureFragment, tt.bundleHash)
			assert.Truef(t, errors.Is(err, tt.expErr), "unexpected error: %v", err)
			assert.Equal(t, tt.expVerified, verified)
		})
	}
}
