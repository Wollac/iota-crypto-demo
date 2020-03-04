package wordlists

import (
	"fmt"
	"strings"

	"github.com/wollac/iota-bip39-demo/pkg/bip39/wordlist"
)

type wordList struct {
	indexes map[string]int
	words   [wordlist.Count]string
}

// newWordList creates a wordList from a white space separate list of words.
// This function will panic if the word count is not 2048 or if there are duplicate words.
func newWordList(s string) wordlist.List {
	fields := strings.Fields(s)
	if l := len(fields); l != wordlist.Count {
		panic(fmt.Sprintf("invalid word count: %d", l))
	}

	indexMap := make(map[string]int, wordlist.Count)
	for i, word := range fields {
		if _, contains := indexMap[word]; contains {
			panic("duplicate word: " + word)
		}
		indexMap[word] = i
	}

	wordList := &wordList{
		indexes: indexMap,
	}
	copy(wordList.words[:], fields)
	return wordList
}

func (w *wordList) Contains(word string) bool {
	_, ok := w.indexes[word]
	return ok
}

func (w *wordList) Word(i int) string {
	return w.words[i]
}

func (w *wordList) Index(word string) int {
	index, ok := w.indexes[word]
	if !ok {
		panic("unknown word")
	}
	return index
}
