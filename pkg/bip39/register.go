package bip39

import (
	"fmt"

	"github.com/wollac/iota-bip39-demo/pkg/bip39/wordlist"
)

var wordLists = make(map[string]func() wordlist.List)

// SetWordList sets the list of words to use for mnemonics.
// The input must be the language key for a registered word list.
func SetWordList(language string) error {
	init, ok := wordLists[language]
	if !ok {
		return fmt.Errorf("word list '%s' is unavailable", language)
	}
	wordList = init()
	return nil
}

// RegisterWordList registers a function that returns a new instance of the given word list.
// This is intended to be called from the init function in packages that implement word lists.
func RegisterWordList(language string, init func() wordlist.List) {
	wordLists[language] = init
}
