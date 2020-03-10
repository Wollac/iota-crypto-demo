package address

import (
	"encoding/hex"
	"errors"
	"fmt"
	"testing"

	"github.com/iotaledger/iota.go/consts"
	"github.com/iotaledger/iota.go/trinary"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGenerate(t *testing.T) {
	var tests = []*struct {
		privateKey string
		expAddress trinary.Hash
		expError   error
	}{
		{"", "", consts.ErrInvalidBytesLength},
		{"9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a", "VP9UQNWTKYOBACDWDVCKLSSAELQMDTOJDBQMIGQCWAEPXUJNNJGKXMCFPZYWEZJWUOTLOEGBKVCPVAPAX", nil},
	}

	for _, tt := range tests {
		t.Run(tt.privateKey, func(t *testing.T) {
			key, err := hex.DecodeString(tt.privateKey)
			require.NoError(t, err)
			fmt.Println(hex.EncodeToString(key))
			address, err := Generate(key, false)
			require.Truef(t, errors.Is(err, tt.expError), "unexpected error: %v", err)
			assert.Equal(t, tt.expAddress, address)
		})
	}
}
