package elliptic

import (
	"crypto/elliptic"
	"math/big"

	"github.com/iotaledger/iota-crypto-demo/pkg/slip10"
	"github.com/iotaledger/iota-crypto-demo/pkg/slip10/elliptic/internal/btccurve"
)

// Curve is an abstract implementation of slip10.Curve based on elliptic.Curve.
type Curve struct {
	elliptic.Curve
}

// HmacKey must be overridden in any valid implementation.
func (Curve) HmacKey() []byte {
	panic("implement me")
}

// Name returns the canonical name of the curve.
func (c Curve) Name() string {
	return c.Params().Name
}

// NewPrivateKey creates a PrivateKey from buf.
// When buf does not correspond to a valid private key, an error is returned.
func (c Curve) NewPrivateKey(buf []byte) (slip10.Key, error) {
	sc := new(big.Int).SetBytes(buf)
	if sc.Sign() == 0 || sc.Cmp(c.Params().N) >= 0 {
		return nil, slip10.ErrInvalidKey
	}
	return &PrivateKey{sc, c}, nil
}

type secp256k1Curve struct {
	Curve
}

func (secp256k1Curve) HmacKey() []byte {
	return []byte("Bitcoin seed")
}

type nist256p1Curve struct {
	Curve
}

func (nist256p1Curve) HmacKey() []byte {
	return []byte("Nist256p1 seed")
}

var secp256k1 = &secp256k1Curve{Curve{btccurve.Secp256k1()}}
var nist256p1 = &nist256p1Curve{Curve{elliptic.P256()}}

// Secp256k1 returns a slip10.Curve which implements secp256k1 (SEC 2, section 2.4.1).
func Secp256k1() slip10.Curve {
	return secp256k1
}

// Nist256p1 returns a slip10.Curve which implements NIST P-256 (FIPS 186-3, section D.2.3).
func Nist256p1() slip10.Curve {
	return nist256p1
}
