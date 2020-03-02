package wordlists

import (
	"fmt"
	"strings"
)

const (
	// IndexBits is the number of bits used to represent a word index.
	IndexBits = 11
	// Count is the number of mnemonic words per word list.
	Count = 1 << IndexBits
)

// WordList represents BIP-39 mnemonic words.
type WordList struct {
	indexes map[string]int
	words   [Count]string
}

// Init creates a WordList from a white space separate list of words.
// This function will panic if the word count is not 2048 or if there are duplicate words.
func Init(s string) *WordList {
	fields := strings.Fields(s)
	if l := len(fields); l != Count {
		panic(fmt.Sprintf("invalid word count: %d", l))
	}

	indexMap := make(map[string]int, Count)
	for i, word := range fields {
		if _, contains := indexMap[word]; contains {
			panic("duplicate word: " + word)
		}
		indexMap[word] = i
	}

	wordList := &WordList{
		indexes: indexMap,
	}
	copy(wordList.words[:], fields)
	return wordList
}

// Contains returns whether the given word is contained in the WordList w.
func (w *WordList) Contains(word string) bool {
	_, ok := w.indexes[word]
	return ok
}

// Word returns the mnemonic word with index i in the WordList w.
func (w *WordList) Word(i int) string {
	return w.words[i]
}

// Index returns the index of the given word in the WordList w.
// It panics when the word is not contained.
func (w *WordList) Index(word string) int {
	index, ok := w.indexes[word]
	if !ok {
		panic("unknown word: " + word)
	}
	return index
}
