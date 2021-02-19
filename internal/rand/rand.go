package rand

import (
	"math/rand"
)

// Reader is a shared instance of a pseudo-random number generator using the math/rand package.
var Reader = readerFunc(rand.Read)

type readerFunc func([]byte) (int, error)

func (f readerFunc) Read(p []byte) (n int, err error) { return f(p) }
