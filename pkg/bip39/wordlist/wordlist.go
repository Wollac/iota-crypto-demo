package wordlist

const (
	// IndexBits is the number of bits used to represent a word index.
	IndexBits = 11
	// Count is the number of mnemonic words per word list.
	Count = 1 << IndexBits
)

// List represents a collection of valid BIP-39 mnemonic words.
type List interface {
	// Contains returns whether the given word is contained in the wordList w.
	Contains(word string) bool

	// Word returns the mnemonic word with index i in the wordList w.
	Word(i int) string

	// Index returns the index [0,2047] of the given word in the wordList w.
	// It panics when the word is not contained in the list.
	Index(word string) int
}
