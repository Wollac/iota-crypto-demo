package bundle

import (
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"github.com/iotaledger/iota.go/bundle"
	"github.com/iotaledger/iota.go/consts"
	"github.com/iotaledger/iota.go/transaction"
	"github.com/iotaledger/iota.go/trinary"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type bundleEssence struct {
	address      trinary.Trytes
	value        int64
	obsoleteTag  trinary.Trytes
	currentIndex uint64
	lastIndex    uint64
	timestamp    uint64
}

var bundleTests = []*struct {
	transfers      []bundle.Transfer
	inputs         []Input
	txTimestamp    uint64
	wantEssence    []bundleEssence
	wantSignatures []trinary.Trytes
	wantErr        error
}{
	// example from the RFC
	{
		transfers: []bundle.Transfer{{
			Address: consts.NullHashTrytes,
			Value:   1000000000,
			Message: "",
			Tag:     "EDTWOFIVEFIVEONENINE9999999",
		}},
		inputs: []Input{{
			KeyPair: ed25519Key("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"),
			Value:   1000000000,
			Tag:     "",
		}},
		txTimestamp: 0,
		wantEssence: []bundleEssence{
			{
				address:      "999999999999999999999999999999999999999999999999999999999999999999999999999999999",
				value:        1000000000,
				obsoleteTag:  "EDTWOFIVEFIVEONENINE9999999",
				currentIndex: 0,
				lastIndex:    1,
				timestamp:    0,
			},
			{
				address:      "VP9UQNWTKYOBACDWDVCKLSSAELQMDTOJDBQMIGQCWAEPXUJNNJGKXMCFPZYWEZJWUOTLOEGBKVCPVAPAX",
				value:        -1000000000,
				obsoleteTag:  "999999999999999999999999999",
				currentIndex: 1,
				lastIndex:    1,
				timestamp:    0,
			},
		},
		wantSignatures: []trinary.Trytes{
			"",
			"MYICDWA9IVBXJ9HXKYUCY9IYZYSDG9DBNAWZFDN9PZRXHAJA9XB9ZAWDR9G99CZA9CICBYVBLAVXOEBXG9HCHVD9SWVCNYTBDYS9MXJZIZHBEBK9M9GCZDSZZYIWUXUWKZPYNWRCNAZXHYNBBBQWLCQZCCEBGWSWSCRX9AXYNZECWDTZJYSZ9WFYXBI9NXD",
		},
		wantErr: nil,
	},
}

func TestGenerate(t *testing.T) {
	for _, tt := range bundleTests {
		txs, err := Generate(tt.transfers, tt.inputs, tt.txTimestamp)
		require.Truef(t, errors.Is(err, tt.wantErr), "unexpected error: %v", err)
		if err != nil {
			return
		}
		assert.Equal(t, tt.wantEssence, getBundleEssence(txs))
		if assert.Equal(t, len(tt.wantSignatures), len(txs)) {
			for i := range txs {
				assert.Equal(t,
					strings.TrimRight(tt.wantSignatures[i], "9"),
					strings.TrimRight(txs[i].SignatureMessageFragment, "9"))
			}
		}
	}
}

func TestValidate(t *testing.T) {
	for _, tt := range bundleTests {
		txs, err := Generate(tt.transfers, tt.inputs, tt.txTimestamp)
		require.Truef(t, errors.Is(err, tt.wantErr), "unexpected error: %v", err)

		err = Validate(txs)
		assert.NoError(t, err)
	}
}

func ed25519Key(s string) ed25519.PrivateKey {
	bytes, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return ed25519.NewKeyFromSeed(bytes)
}

func getBundleEssence(txs []transaction.Transaction) []bundleEssence {
	var essence []bundleEssence
	for _, tx := range txs {
		essence = append(essence, bundleEssence{
			address:      tx.Address,
			value:        tx.Value,
			obsoleteTag:  tx.ObsoleteTag,
			currentIndex: tx.CurrentIndex,
			lastIndex:    tx.LastIndex,
			timestamp:    tx.Timestamp,
		})
	}
	return essence
}
