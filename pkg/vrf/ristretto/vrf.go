// Package ristretto implements a VRF using ristretto255 and BLAKE2b-512 similar to draft-irtf-cfrg-vrf-15.
package ristretto

import (
	cryptorand "crypto/rand"
	"errors"
	"fmt"
	"io"
	"strconv"

	"github.com/gtank/ristretto255"
	"golang.org/x/crypto/blake2b"
)

const (
	// PublicKeySize is the size, in bytes, of public keys as used in this package.
	PublicKeySize = 32
	// PrivateKeySize is the size, in bytes, of private keys as used in this package.
	PrivateKeySize = SeedSize + PublicKeySize
	// SeedSize is the size, in bytes, of private key seeds. These are the private key representations used by RFC 8032.
	SeedSize = 32
	// ProofSize is the size, in bytes, of proofs.
	ProofSize = ptLen + cLen + qLen
)

type (
	PublicKey  []byte
	PrivateKey []byte
)

// GenerateKey generates a public/private key pair using entropy from rand.
// If rand is nil, crypto/rand.Reader will be used.
func GenerateKey(rand io.Reader) (PublicKey, PrivateKey, error) {
	if rand == nil {
		rand = cryptorand.Reader
	}

	seed := make([]byte, SeedSize)
	if _, err := io.ReadFull(rand, seed); err != nil {
		return nil, nil, err
	}

	privateKey := NewKeyFromSeed(seed)
	publicKey := make([]byte, PublicKeySize)
	copy(publicKey, privateKey[32:])

	return publicKey, privateKey, nil
}

// NewKeyFromSeed calculates a private key from a seed.
// It will panic if len(seed) is not SeedSize.
func NewKeyFromSeed(seed []byte) PrivateKey {
	// when NewKeyFromSeed is inlined, the returned signature can be stack-allocated
	privateKey := make([]byte, PrivateKeySize)
	newKeyFromSeed(privateKey, seed)
	return privateKey
}

func newKeyFromSeed(privateKey, seed []byte) {
	if l := len(seed); l != SeedSize {
		panic("ed25519: bad seed length: " + strconv.Itoa(l))
	}

	hashedSKString := blake2b.Sum512(seed)
	x, err := new(ristretto255.Scalar).SetUniformBytes(hashedSKString[:64])
	if err != nil {
		panic("ristretto: internal error: setting scalar failed")
	}
	Y := new(ristretto255.Element).ScalarBaseMult(x)
	publicKey := Y.Bytes()

	copy(privateKey, seed)
	copy(privateKey[32:], publicKey)
}

const (
	ptLen = 32 // length of a curve point in bytes
	cLen  = 16 // length of a challenge scalar in bytes
	qLen  = 32 // length of a scalar in bytes

	hLen = 64 // length of a checksum in bytes
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
	gamma *ristretto255.Element
	c     *ristretto255.Scalar
	s     *ristretto255.Scalar
}

// Hash returns the VRF hash output corresponding to p.
// Hash should be run only on p that is known to have been produced by Prove, or from within Verify.
func (p *Proof) Hash() []byte {
	h, _ := blake2b.New512(nil)
	h.Write(suiteString)
	h.Write(proofToHashDomainSeparatorFront)
	h.Write(p.gamma.Bytes())
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
	p.gamma, err = new(ristretto255.Element).SetCanonicalBytes(data[:ptLen])
	if err != nil {
		return fmt.Errorf("invalid point: %w", err)
	}

	cString := make([]byte, qLen)
	copy(cString, data[ptLen:(ptLen+cLen)])
	p.c, err = new(ristretto255.Scalar).SetCanonicalBytes(cString)
	if err != nil {
		panic("ristretto: internal error: setting challenge scalar failed")
	}

	p.s, err = new(ristretto255.Scalar).SetCanonicalBytes(data[(ptLen + cLen):])
	if err != nil {
		return fmt.Errorf("invalid proof: %w", err)
	}

	return nil
}

// Prove computes the VRF proof for the input alpha.
func Prove(privateKey PrivateKey, alpha []byte) *Proof {
	if l := len(privateKey); l != PrivateKeySize {
		panic("ristretto: bad private key length: " + strconv.Itoa(l))
	}
	seed, publicKey := privateKey[:SeedSize], privateKey[SeedSize:]

	// Use SK to derive the VRF secret scalar x and the VRF public key Y = x*B
	hashedSKString := blake2b.Sum512(seed)
	x, err := new(ristretto255.Scalar).SetUniformBytes(hashedSKString[:64])
	if err != nil {
		panic("ristretto: internal error: setting scalar failed")
	}
	Y, err := new(ristretto255.Element).SetCanonicalBytes(publicKey)
	if err != nil {
		panic("ristretto: invalid public key part: " + err.Error())
	}

	// H = ECVRF_encode_to_curve(encode_to_curve_salt, alpha_string)
	H := hashToCurve(publicKey, alpha)

	// Gamma = x*H
	Gamma := new(ristretto255.Element).ScalarMult(x, H)

	// k = ECVRF_nonce_generation(SK, h_string)
	kh, _ := blake2b.New512(nil)
	kh.Write(x.Bytes())
	kh.Write(Y.Bytes())
	kh.Write(H.Bytes())
	kString := make([]byte, 0, hLen)
	kString = kh.Sum(kString)
	k, err := new(ristretto255.Scalar).SetUniformBytes(kString)
	if err != nil {
		panic("ristretto: internal error: setting scalar failed")
	}

	// c = ECVRF_challenge_generation(Y, H, Gamma, k*B, k*H)
	c := challengeGeneration(Y, H, Gamma, new(ristretto255.Element).ScalarBaseMult(k), new(ristretto255.Element).ScalarMult(k, H))
	// s = (k + c*x) mod q
	s := k.Add(k, x.Multiply(c, x))

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
		panic("ristretto: bad public key length: " + strconv.Itoa(l))
	}

	Y, err := new(ristretto255.Element).SetCanonicalBytes(publicKey)
	if err != nil {
		return false, nil
	}
	// D = ECVRF_decode_proof(pi_string)
	D, err := new(Proof).SetBytes(piString)
	if err != nil {
		return false, nil
	}

	// H = ECVRF_encode_to_curve(encode_to_curve_salt, alpha_string)
	H := hashToCurve(publicKey, alpha)

	// U = s*B - c*Y
	U := new(ristretto255.Element).Negate(Y)
	U.VarTimeDoubleScalarBaseMult(D.c, U, D.s)

	// V = s*H - c*Gamma
	V := new(ristretto255.Element).Negate(D.gamma)
	V.VarTimeMultiScalarMult([]*ristretto255.Scalar{D.s, D.c}, []*ristretto255.Element{H, V})

	// c' = ECVRF_challenge_generation(Y, H, Gamma, U, V)
	checkC := challengeGeneration(Y, H, D.gamma, U, V)
	// If c and c' are equal, output ("VALID", ECVRF_proof_to_hash(pi_string))
	if D.c.Equal(checkC) != 1 {
		return false, nil
	}

	return true, D.Hash()
}

func hashToCurve(encodeToCurveSalt []byte, alphaString []byte) *ristretto255.Element {
	h, _ := blake2b.New512(nil)
	h.Write(suiteString)
	h.Write(encodeToCurveDomainSeparatorFront)
	h.Write(encodeToCurveSalt)
	h.Write(alphaString)
	h.Write(encodeToCurveDomainSeparatorBack)

	hashString := make([]byte, 0, hLen)
	hashString = h.Sum(hashString)
	H, err := new(ristretto255.Element).SetUniformBytes(hashString)
	if err != nil {
		panic("internal error")
	}

	return H
}

func challengeGeneration(P1, P2, P3, P4, P5 *ristretto255.Element) *ristretto255.Scalar {
	h, _ := blake2b.New512(nil)
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
	c, err := new(ristretto255.Scalar).SetCanonicalBytes(truncatedCString)
	if err != nil {
		// this should not happen as cLen is significantly smaller than qLen
		panic("ristretto: internal error: setting scalar failed")
	}

	return c
}
