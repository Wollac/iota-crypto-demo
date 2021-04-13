package curl

import (
	"github.com/iotaledger/iota.go/consts"
)

const (
	// StateSize is the size of the Curl hash function.
	StateSize = consts.HashTrinarySize * 3

	// NumRounds is the number of rounds in a Curl transform.
	NumRounds = 81
)

// SpongeDirection indicates the direction trits are flowing through the sponge.
type SpongeDirection int

const (
	// SpongeAbsorbing indicates that the sponge is absorbing input.
	SpongeAbsorbing SpongeDirection = iota
	// SpongeSqueezing indicates that the sponge is being squeezed.
	SpongeSqueezing
)
