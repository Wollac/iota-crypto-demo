package wordlists

import (
	"io/ioutil"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const referenceURL = "https://raw.githubusercontent.com/bitcoin/bips/master/bip-0039/"

func testWordListHash(t *testing.T, list string, name string) {
	resp, err := http.Get(referenceURL + name)
	require.NoError(t, err)
	defer func() { assert.NoError(t, resp.Body.Close()) }()

	body, err := ioutil.ReadAll(resp.Body)
	require.NoError(t, err)

	referenceList := string(body)
	assert.Equal(t, referenceList, list, "word lists do not match")
}
