// Package ec implements the ECVRF-EDWARDS25519-SHA512-TAI VRF according to draft-irtf-cfrg-vrf-15.
package ec

import (
	"crypto/sha512"
	"errors"
	"fmt"
	"io"
	"strconv"

	"filippo.io/edwards25519"
	"github.com/wollac/iota-crypto-demo/pkg/ed25519"
)

const (
	// PublicKeySize is the size, in bytes, of public keys as used in this package.
	PublicKeySize = 32
	// PrivateKeySize is the size, in bytes, of private keys as used in this package.
	PrivateKeySize = 64
	// SeedSize is the size, in bytes, of private key seeds. These are the private key representations used by RFC 8032.
	SeedSize = 32
	// ProofSize is the size, in bytes, of proofs.
	ProofSize = ptLen + cLen + qLen
)

type (
	PublicKey  = ed25519.PublicKey
	PrivateKey = ed25519.PrivateKey
)

// GenerateKey generates a public/private key pair using entropy from rand.
// If rand is nil, crypto/rand.Reader will be used.
func GenerateKey(rand io.Reader) (PublicKey, PrivateKey, error) {
	return ed25519.GenerateKey(rand)
}

// NewKeyFromSeed calculates a private key from a seed. It will panic if
// len(seed) is not SeedSize. This function is provided for interoperability
// with RFC 8032. RFC 8032's private keys correspond to seeds in this
// package.
func NewKeyFromSeed(seed []byte) ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed(seed)
}

const (
	ptLen = 32 // length of a curve point in bytes
	cLen  = 16 // length of a challenge scalar in bytes
	qLen  = 32 // length of a scalar in bytes

	hLen = sha512.Size // length of a checksum in bytes
)

var (
	suiteString = []byte{0x03}

	encodeToCurveDomainSeparatorFront = []byte{0x01}
	encodeToCurveDomainSeparatorBack  = []byte{0x00}

	challengeGenerationDomainSeparatorFront = []byte{0x02}
	challengeGenerationDomainSeparatorBack  = []byte{0x00}

	proofToHashDomainSeparatorFront = []byte{0x03}
	proofToHashDomainSeparatorBack  = []byte{0x00}
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
		return errors.New("invalid encoding length")
	}

	var err error
	p.gamma, err = new(edwards25519.Point).SetBytes(data[:ptLen])
	if err != nil {
		return fmt.Errorf("invalid point: %w", err)
	}

	cString := make([]byte, qLen)
	copy(cString, data[ptLen:(ptLen+cLen)])
	p.c, err = edwards25519.NewScalar().SetCanonicalBytes(cString)
	if err != nil {
		panic("ecvrf: internal error: setting challenge scalar failed")
	}

	p.s, err = edwards25519.NewScalar().SetCanonicalBytes(data[(ptLen + cLen):])
	if err != nil {
		return fmt.Errorf("invalid proof: %w", err)
	}

	return nil
}

// Prove computes the VRF proof for the input alpha.
func Prove(privateKey PrivateKey, alpha []byte) *Proof {
	if l := len(privateKey); l != PrivateKeySize {
		panic("ecvrf: bad private key length: " + strconv.Itoa(l))
	}
	seed, publicKey := privateKey[:SeedSize], privateKey[SeedSize:]

	// Use SK to derive the VRF secret scalar x and the VRF public key Y = x*B
	hashedSkString := sha512.Sum512(seed)
	x, err := edwards25519.NewScalar().SetBytesWithClamping(hashedSkString[:32])
	if err != nil {
		panic("ecvrf: internal error: setting scalar failed")
	}
	Y, err := new(edwards25519.Point).SetBytes(publicKey)
	if err != nil {
		panic("ecvrf: invalid public key part: " + err.Error())
	}

	// H = ECVRF_encode_to_curve(encode_to_curve_salt, alpha_string)
	H := encodeToCurveTryAndIncrement(publicKey, alpha)

	// Gamma = x*H
	Gamma := new(edwards25519.Point).ScalarMult(x, H)

	// k = ECVRF_nonce_generation(SK, h_string)
	kh := sha512.New()
	kh.Write(hashedSkString[32:])
	kh.Write(H.Bytes())
	kString := make([]byte, 0, hLen)
	kString = kh.Sum(kString)
	k, err := edwards25519.NewScalar().SetUniformBytes(kString)
	if err != nil {
		panic("ecvrf: internal error: setting scalar failed")
	}

	// c = ECVRF_challenge_generation(Y, H, Gamma, k*B, k*H)
	c := challengeGeneration(Y, H, Gamma, new(edwards25519.Point).ScalarBaseMult(k), new(edwards25519.Point).ScalarMult(k, H))
	// s = (k + c*x) mod q
	s := edwards25519.NewScalar().MultiplyAdd(c, x, k)

	return &Proof{Gamma, c, s}
}

// ProofToHash computes the VRF hash output corresponding to a VRF proof.
// ProofToHash should be run only on piString that is known to have been produced by Prove, or from within Verify.
func ProofToHash(piString []byte) ([]byte, error) {
	pi, err := new(Proof).SetBytes(piString)
	if err != nil {
		return nil, err
	}

	return pi.Hash(), nil
}

// Verify reports whether piString is a valid proof of alpha by publicKey.
// If the proof is valid, Verify also returns the VRF hash output.
func Verify(publicKey PublicKey, alpha []byte, piString []byte) (bool, []byte) {
	if l := len(publicKey); l != PublicKeySize {
		panic("ecvrf: bad public key length: " + strconv.Itoa(l))
	}

	Y, err := new(edwards25519.Point).SetBytes(publicKey)
	if err != nil {
		return false, nil
	}
	D, err := new(Proof).SetBytes(piString)
	if err != nil {
		return false, nil
	}

	// H = ECVRF_encode_to_curve(encode_to_curve_salt, alpha_string)
	H := encodeToCurveTryAndIncrement(publicKey, alpha)

	// U = s*B - c*Y
	U := new(edwards25519.Point).Negate(Y)
	U.VarTimeDoubleScalarBaseMult(D.c, U, D.s)

	// V = s*H - c*Gamma
	V := new(edwards25519.Point).Negate(D.gamma)
	V.VarTimeMultiScalarMult([]*edwards25519.Scalar{D.s, D.c}, []*edwards25519.Point{H, V})

	// c' = ECVRF_challenge_generation(Y, H, Gamma, U, V)
	checkC := challengeGeneration(Y, H, D.gamma, U, V)
	// If c and c' are equal, output ("VALID", ECVRF_proof_to_hash(pi_string))
	if D.c.Equal(checkC) != 1 {
		return false, nil
	}

	return true, D.Hash()
}

func encodeToCurveTryAndIncrement(encodeToCurveSalt []byte, alphaString []byte) *edwards25519.Point {
	h := sha512.New()
	hashString := make([]byte, 0, hLen)
	H := new(edwards25519.Point)
	for ctr := 0; ctr <= 0xff; ctr++ {
		h.Write(suiteString)
		h.Write(encodeToCurveDomainSeparatorFront)
		h.Write(encodeToCurveSalt)
		h.Write(alphaString)
		h.Write([]byte{byte(ctr)})
		h.Write(encodeToCurveDomainSeparatorBack)

		hashString = h.Sum(hashString[:0])
		if _, err := H.SetBytes(hashString[:ptLen]); err == nil {
			return H.MultByCofactor(H)
		}
		h.Reset()
	}

	panic("ecvrf: unable to compute hash")
}

func challengeGeneration(P1, P2, P3, P4, P5 *edwards25519.Point) *edwards25519.Scalar {
	h := sha512.New()
	h.Write(suiteString)
	h.Write(challengeGenerationDomainSeparatorFront)
	h.Write(P1.Bytes())
	h.Write(P2.Bytes())
	h.Write(P3.Bytes())
	h.Write(P4.Bytes())
	h.Write(P5.Bytes())
	h.Write(challengeGenerationDomainSeparatorBack)

	cString := make([]byte, 0, hLen)
	cString = h.Sum(cString)

	// truncate the string to the desired length
	truncatedCString := make([]byte, qLen)
	copy(truncatedCString, cString[:cLen])
	c, err := edwards25519.NewScalar().SetCanonicalBytes(truncatedCString)
	if err != nil {
		// this should not happen as cLen is significantly smaller than qLen
		panic("ecvrf: internal error: setting scalar failed")
	}

	return c
}
