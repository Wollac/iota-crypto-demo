package wordlists

import (
	"crypto/sha256"
	"io/ioutil"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const url = "https://raw.githubusercontent.com/bitcoin/bips/master/bip-0039/"

func testWordListHash(t *testing.T, list string, name string) {
	resp, err := http.Get(url + name)
	require.NoError(t, err)
	defer func() { assert.NoError(t, resp.Body.Close()) }()

	body, err := ioutil.ReadAll(resp.Body)
	require.NoError(t, err)

	bodyHash := sha256.Sum256(body)
	assert.Equal(t, bodyHash, sha256.Sum256([]byte(list)), "word list hash does not match")
}
