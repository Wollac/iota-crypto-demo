package wordlists

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestEnglish(t *testing.T) {
	assert.NotPanics(t, func() { Init(English) })
	testWordListHash(t, English, "english.txt")
}
