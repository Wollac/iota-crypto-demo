package vrf

import (
	"crypto/sha512"
	"fmt"

	"filippo.io/edwards25519"
)

// Proof represents a VRF proof.
type Proof struct {
	gamma *edwards25519.Point
	c     *edwards25519.Scalar
	s     *edwards25519.Scalar
}

// Hash returns the VRF hash output corresponding to p.
// Hash should be run only on p that is known to have been produced by Prove, or from within Verify.
func (p *Proof) Hash() []byte {
	gamma := new(edwards25519.Point).MultByCofactor(p.gamma)

	h := sha512.New()
	h.Write(suiteString)
	h.Write(proofToHashDomainSeparatorFront)
	h.Write(gamma.Bytes())
	h.Write(proofToHashDomainSeparatorBack)
	betaString := make([]byte, 0, hLen)
	betaString = h.Sum(betaString)

	return betaString
}

// Bytes returns the canonical 80-byte encoding of p.
func (p *Proof) Bytes() []byte {
	piString := make([]byte, ProofSize)
	copy(piString[:ptLen], p.gamma.Bytes())
	copy(piString[ptLen:(ptLen+cLen)], p.c.Bytes())
	copy(piString[(ptLen+cLen):], p.s.Bytes())

	return piString
}

// SetBytes sets p = x, where x is an 80-byte encoding of p.
// If x does not represent a valid proof, SetBytes returns nil and an error.
func (p *Proof) SetBytes(x []byte) (*Proof, error) {
	if err := p.UnmarshalBinary(x); err != nil {
		return nil, err
	}

	return p, nil
}

func (p *Proof) MarshalBinary() ([]byte, error) {
	return p.Bytes(), nil
}

func (p *Proof) UnmarshalBinary(data []byte) error {
	if l := len(data); l != ProofSize {
		return fmt.Errorf("invalid proof length: %d", l)
	}

	var err error
	p.gamma, err = newPointFromCanonicalBytes(data[:ptLen])
	if err != nil {
		return fmt.Errorf("invalid point: %w", err)
	}

	cString := make([]byte, qLen)
	copy(cString, data[ptLen:(ptLen+cLen)])
	p.c, err = new(edwards25519.Scalar).SetCanonicalBytes(cString)
	if err != nil {
		panic("edwards: internal error: setting challenge scalar failed")
	}

	p.s, err = new(edwards25519.Scalar).SetCanonicalBytes(data[(ptLen + cLen):])
	if err != nil {
		return fmt.Errorf("invalid proof: %w", err)
	}

	return nil
}
