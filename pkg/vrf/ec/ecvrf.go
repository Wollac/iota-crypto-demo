package ec

import (
	"bytes"
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
)

type (
	PublicKey  = ed25519.PublicKey
	PrivateKey = ed25519.PrivateKey
)

func GenerateKey(rand io.Reader) (PublicKey, PrivateKey, error) {
	return ed25519.GenerateKey(rand)
}

func NewKeyFromSeed(seed []byte) ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed(seed)
}

const (
	ptLen = 32                  // length of a curve point in bytes
	cLen  = 16                  // length of a challenge scalar in bytes
	qLen  = 32                  // length of a scalar in bytes
	piLen = ptLen + cLen + qLen // length of a proof in bytes

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

type Proof struct {
	gamma *edwards25519.Point
	c     *edwards25519.Scalar
	s     *edwards25519.Scalar
}

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

func (p *Proof) Bytes() []byte {
	piString := make([]byte, piLen)
	copy(piString[:ptLen], p.gamma.Bytes())
	copy(piString[ptLen:(ptLen+cLen)], p.c.Bytes())
	copy(piString[(ptLen+cLen):], p.s.Bytes())

	return piString
}

func (p *Proof) SetBytes(data []byte) (*Proof, error) {
	if err := p.UnmarshalBinary(data); err != nil {
		return nil, err
	}

	return p, nil
}

func (p *Proof) MarshalBinary() ([]byte, error) {
	return p.Bytes(), nil
}

func (p *Proof) UnmarshalBinary(data []byte) error {
	if l := len(data); l != piLen {
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

func Prove(privateKey PrivateKey, alphaString []byte) *Proof {
	if l := len(privateKey); l != PrivateKeySize {
		panic("ecvrf: bad private key length: " + strconv.Itoa(l))
	}
	secretKey, publicKey := privateKey[:SeedSize], privateKey[SeedSize:]

	hashedSkString := sha512.Sum512(secretKey)
	x, err := edwards25519.NewScalar().SetBytesWithClamping(hashedSkString[:32])
	if err != nil {
		panic("ecvrf: internal error: setting scalar failed")
	}
	Y, err := new(edwards25519.Point).SetBytes(publicKey)
	if err != nil {
		panic("ecvrf: invalid public key part: " + err.Error())
	}

	H := encodeToCurveTryAndIncrement(publicKey, alphaString)
	hString := H.Bytes()

	Gamma := new(edwards25519.Point).ScalarMult(x, H)

	k := nonceGenerationRFC8032(hashedSkString[:], hString)

	c := challengeGeneration(Y, H, Gamma, new(edwards25519.Point).ScalarBaseMult(k), new(edwards25519.Point).ScalarMult(k, H))
	s := edwards25519.NewScalar().MultiplyAdd(c, x, k)

	return &Proof{Gamma, c, s}
}

func ProofToHash(piString []byte) ([]byte, error) {
	pi, err := new(Proof).SetBytes(piString)
	if err != nil {
		return nil, err
	}

	return pi.Hash(), nil
}

func Verify(publicKey PublicKey, alphaString []byte, piString []byte) (bool, []byte) {
	if l := len(publicKey); l != PublicKeySize {
		panic("ecvrf: bad public key length: " + strconv.Itoa(l))
	}

	Y, err := (&edwards25519.Point{}).SetBytes(publicKey)
	if err != nil {
		return false, nil
	}
	D, err := new(Proof).SetBytes(piString)
	if err != nil {
		return false, nil
	}

	H := encodeToCurveTryAndIncrement(publicKey, alphaString)

	U := new(edwards25519.Point).ScalarBaseMult(D.s)
	U.Subtract(U, new(edwards25519.Point).ScalarMult(D.c, Y))

	V := new(edwards25519.Point).ScalarMult(D.s, H)
	V.Subtract(V, new(edwards25519.Point).ScalarMult(D.c, D.gamma))

	checkC := challengeGeneration(Y, H, D.gamma, U, V)
	if !bytes.Equal(D.c.Bytes(), checkC.Bytes()) {
		return false, nil
	}

	return true, D.Hash()
}

func nonceGenerationRFC8032(hashedSkString []byte, hString []byte) *edwards25519.Scalar {
	truncatedHashedSkString := hashedSkString[32:64]

	h := sha512.New()
	h.Write(truncatedHashedSkString)
	h.Write(hString)
	kString := make([]byte, 0, hLen)
	kString = h.Sum(kString)
	k, err := edwards25519.NewScalar().SetUniformBytes(kString)
	if err != nil {
		panic("ecvrf: internal error: setting scalar failed")
	}

	return k
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
