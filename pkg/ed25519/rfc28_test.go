package ed25519_test

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/wollac/iota-crypto-demo/internal/hexutil"
	"github.com/wollac/iota-crypto-demo/pkg/bech32/address"
	"github.com/wollac/iota-crypto-demo/pkg/ed25519"
)

type testCase struct {
	Address   hexutil.Bytes `json:"address"`
	Message   hexutil.Bytes `json:"message"`
	PublicKey hexutil.Bytes `json:"pub_key"`
	Signature hexutil.Bytes `json:"signature"`
	Valid     bool          `json:"valid"`
}

func verify(tv *testCase) bool {
	// check whether the address is correct first
	addr := address.AddressFromPublicKey(ed25519.PublicKey(tv.PublicKey))
	if !bytes.Equal(addr.Bytes(), tv.Address) {
		return false
	}
	// then check the actual signature
	return ed25519.Verify(ed25519.PublicKey(tv.PublicKey), tv.Message, tv.Signature)
}

func TestRFC28(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("testdata", "0028-test.json"))
	require.NoError(t, err)

	var tvs []*testCase
	require.NoError(t, json.Unmarshal(b, &tvs))

	for _, tv := range tvs {
		t.Run("", func(t *testing.T) {
			require.Equal(t, tv.Valid, verify(tv))
		})
	}
}
