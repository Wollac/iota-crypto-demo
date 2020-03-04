package wordlists

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestJapanese(t *testing.T) {
	assert.NotPanics(t, func() { Japanese() })
	testWordListHash(t, japanese, "japanese.txt")
}
