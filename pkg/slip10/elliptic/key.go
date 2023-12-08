package elliptic

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"fmt"
	"math/big"

	"github.com/iotaledger/iota-crypto-demo/pkg/slip10"
)

// PrivateKey implements slip10.Key and represents a private key for elliptic.Curve.
type PrivateKey struct {
	K     *big.Int
	Curve elliptic.Curve
}

// PublicKey implements slip10.Key and  represents a public key for elliptic.Curve.
type PublicKey struct {
	X, Y  *big.Int
	Curve elliptic.Curve
}

// Bytes returns the SLIP-10 serialization of the key.
func (p *PrivateKey) Bytes() []byte {
	buf := make([]byte, slip10.PrivateKeySize)
	return p.K.FillBytes(buf)
}

// IsPrivate always returns true.
func (*PrivateKey) IsPrivate() bool {
	return true
}

// Public returns the corresponding PublicKey.
func (p *PrivateKey) Public() slip10.Key {
	x, y := p.Curve.ScalarBaseMult(p.K.Bytes())
	return &PublicKey{x, y, p.Curve}
}

// Shift derives a new PrivateKey using the provided additive shift.
// It returns ErrInvalidKey if the shift leads to an invalid key.
func (p *PrivateKey) Shift(buf []byte) (slip10.Key, error) {
	sc1 := new(big.Int).SetBytes(buf)
	if sc1.Cmp(p.Curve.Params().N) >= 0 {
		return nil, slip10.ErrInvalidKey
	}

	sc1.Add(sc1, p.K)
	sc1.Mod(sc1, p.Curve.Params().N)
	if sc1.Sign() == 0 {
		return nil, slip10.ErrInvalidKey
	}

	return &PrivateKey{sc1, p.Curve}, nil
}

// ECDSAPrivateKey returns the corresponding ecdsa.PrivateKey.
func (p *PrivateKey) ECDSAPrivateKey() *ecdsa.PrivateKey {
	priv := new(ecdsa.PrivateKey)
	priv.PublicKey.Curve = p.Curve
	priv.D = p.K
	priv.PublicKey.X, priv.PublicKey.Y = p.Curve.ScalarBaseMult(p.K.Bytes())
	return priv
}

func (p *PrivateKey) String() string {
	return fmt.Sprintf("{K:%s Curve:%s}", p.K, p.Curve.Params().Name)
}

// Bytes returns the SLIP-10 serialization of the key.
func (p *PublicKey) Bytes() []byte {
	return elliptic.MarshalCompressed(p.Curve, p.X, p.Y)
}

// IsPrivate always returns false.
func (*PublicKey) IsPrivate() bool {
	return false
}

// Public returns a reference to itself.
func (p *PublicKey) Public() slip10.Key {
	return p
}

// Shift derives a new PublicKey using the provided additive shift.
// It returns ErrInvalidKey if the shift leads to an invalid key.
func (p *PublicKey) Shift(bytes []byte) (slip10.Key, error) {
	if new(big.Int).SetBytes(bytes).Cmp(p.Curve.Params().N) >= 0 {
		return nil, slip10.ErrInvalidKey
	}

	x2, y2 := p.Curve.ScalarBaseMult(bytes)
	x, y := p.Curve.Add(p.X, p.Y, x2, y2)
	// the point at infinity (0, 0) is invalid
	if x.Sign() == 0 && y.Sign() == 0 {
		return nil, slip10.ErrInvalidKey
	}

	return &PublicKey{x, y, p.Curve}, nil
}

// ECDSAPublicKey returns the corresponding ecdsa.PublicKey.
func (p *PublicKey) ECDSAPublicKey() *ecdsa.PublicKey {
	return &ecdsa.PublicKey{
		Curve: p.Curve,
		X:     p.X,
		Y:     p.Y,
	}
}

func (p *PublicKey) String() string {
	return fmt.Sprintf("{X:%s Y:%s Curve:%s}", p.X, p.Y, p.Curve.Params().Name)
}
