package convert

import (
	"fmt"
	"strings"

	"github.com/iotaledger/iota.go/consts"
	"github.com/iotaledger/iota.go/trinary"
)

func tryteToTryteValue(t byte) int8 {
	return trinary.TryteToTryteValueLUT[t-'9']
}

func BytesToTrytes(bytes []byte) (trinary.Trytes, error) {
	if err := ValidBytes(bytes); err != nil {
		return "", err
	}
	return MustBytesToTrytes(bytes), nil
}

func MustBytesToTrytes(bytes []byte) trinary.Trytes {
	var trytes strings.Builder
	trytes.Grow(len(bytes) * 2)

	for i := range bytes {
		// convert to un-balanced ternary first
		v := int(int8(bytes[i])) + (consts.TryteRadix/2)*consts.TryteRadix + consts.TryteRadix/2
		quo, rem := v/consts.TryteRadix, v%consts.TryteRadix
		trytes.WriteByte(trinary.TryteValueToTyteLUT[rem])
		trytes.WriteByte(trinary.TryteValueToTyteLUT[quo])
	}
	return trytes.String()
}

func ValidBytes(bytes []byte) error {
	if len(bytes) == 0 {
		return consts.ErrInvalidBytesLength
	}
	return nil
}

func TrytesToBytes(trytes trinary.Trytes) ([]byte, error) {
	if err := ValidTrytesForBytes(trytes); err != nil {
		return nil, err
	}
	return MustTrytesToBytes(trytes), nil
}

func MustTrytesToBytes(trytes trinary.Trytes) []byte {
	trytesLength := len(trytes)

	bytes := make([]byte, trytesLength/2)
	for i := 0; i < trytesLength; i += 2 {
		v := tryteToTryteValue(trytes[i]) + tryteToTryteValue(trytes[i+1])*consts.TryteRadix

		bytes[i/2] = byte(v)
	}
	return bytes
}

func ValidTrytesForBytes(trytes trinary.Trytes) error {
	tryteLen := len(trytes)
	if tryteLen < 1 || tryteLen%2 != 0 {
		return fmt.Errorf("%w: length must be even", consts.ErrInvalidTrytes)
	}
	if err := trinary.ValidTrytes(trytes); err != nil {
		return err
	}
	for i := 0; i < tryteLen; i += 2 {
		v := int(tryteToTryteValue(trytes[i])) + int(tryteToTryteValue(trytes[i+1]))*consts.TryteRadix
		if int(int8(v)) != v {
			return fmt.Errorf("%w: at index %d (trytes: %s)", consts.ErrInvalidTrytes, i, trytes[i:i+2])
		}
	}
	return nil
}
