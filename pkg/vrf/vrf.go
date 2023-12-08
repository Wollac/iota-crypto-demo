// Package vrf implements the ECVRF-EDWARDS25519-SHA512-TAI VRF according to draft-irtf-cfrg-vrf-15.
package vrf

import (
	"crypto/sha512"
	"io"
	"strconv"

	"filippo.io/edwards25519"
	"github.com/iotaledger/iota-crypto-demo/pkg/ed25519"
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
	PublicKey  = ed25519.PublicKey
	PrivateKey = ed25519.PrivateKey
)

// GenerateKey generates a public/private key pair using entropy from rand.
// If rand is nil, crypto/rand.Reader will be used.
// The key generation is 100% compatible with crypto/ed25519.
func GenerateKey(rand io.Reader) (PublicKey, PrivateKey, error) {
	return ed25519.GenerateKey(rand)
}

// NewKeyFromSeed calculates a private key from a seed.
// It will panic if len(seed) is not SeedSize.
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

	identityPoint = edwards25519.NewIdentityPoint()
)

// Prove computes the VRF proof for the input alpha.
func Prove(privateKey PrivateKey, alpha []byte) *Proof {
	if l := len(privateKey); l != PrivateKeySize {
		panic("edwards: bad private key length: " + strconv.Itoa(l))
	}
	seed, publicKey := privateKey[:SeedSize], privateKey[SeedSize:]

	// Use SK to derive the VRF secret scalar x and the VRF public key Y = x*B
	hashedSKString := sha512.Sum512(seed)
	x, err := new(edwards25519.Scalar).SetBytesWithClamping(hashedSKString[:32])
	if err != nil {
		panic("edwards: internal error: setting scalar failed")
	}

	// H = ECVRF_encode_to_curve(encode_to_curve_salt, alpha_string)
	H := encodeToCurveTryAndIncrement(publicKey, alpha)
	hString := H.Bytes()

	// Gamma = x*H
	Gamma := new(edwards25519.Point).ScalarMult(x, H)

	// k = ECVRF_nonce_generation(SK, h_string)
	kh := sha512.New()
	kh.Write(hashedSKString[32:])
	kh.Write(hString)
	kString := make([]byte, 0, hLen)
	kString = kh.Sum(kString)
	k, err := new(edwards25519.Scalar).SetUniformBytes(kString)
	if err != nil {
		panic("edwards: internal error: setting scalar failed")
	}

	// c = ECVRF_challenge_generation(Y, H, Gamma, k*B, k*H)
	c := challengeGeneration(publicKey, hString, Gamma, new(edwards25519.Point).ScalarBaseMult(k), new(edwards25519.Point).ScalarMult(k, H))
	// s = (k + c*x) mod q
	s := k.MultiplyAdd(c, x, k)

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
		panic("edwards: bad public key length: " + strconv.Itoa(l))
	}

	Y, err := newPointFromCanonicalBytes(publicKey)
	if err != nil {
		return false, nil
	}
	// If validate_key, run ECVRF_validate_key(Y)
	if !validateKey(Y) {
		return false, nil
	}
	// D = ECVRF_decode_proof(pi_string)
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
	checkC := challengeGeneration(publicKey, H.Bytes(), D.gamma, U, V)
	// If c and c' are equal, output ("VALID", ECVRF_proof_to_hash(pi_string))
	if D.c.Equal(checkC) != 1 {
		return false, nil
	}

	return true, D.Hash()
}

func encodeToCurveTryAndIncrement(encodeToCurveSalt []byte, alphaString []byte) *edwards25519.Point {
	h := sha512.New()
	hashString := make([]byte, 0, hLen)
	for ctr := 0; ctr <= 0xff; ctr++ {
		h.Write(suiteString)
		h.Write(encodeToCurveDomainSeparatorFront)
		h.Write(encodeToCurveSalt)
		h.Write(alphaString)
		h.Write([]byte{byte(ctr)})
		h.Write(encodeToCurveDomainSeparatorBack)

		hashString = h.Sum(hashString[:0])
		if H, err := newPointFromCanonicalBytes(hashString[:ptLen]); err == nil {
			// set H = cofactor*H
			H.MultByCofactor(H)
			// only return prime order H
			if H.Equal(identityPoint) != 1 {
				return H
			}
		}
		h.Reset()
	}

	panic("edwards: unable to compute hash")
}

func challengeGeneration(P1, P2 []byte, P3, P4, P5 *edwards25519.Point) *edwards25519.Scalar {
	h := sha512.New()
	h.Write(suiteString)
	h.Write(challengeGenerationDomainSeparatorFront)
	h.Write(P1)
	h.Write(P2)
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
		panic("edwards: internal error: setting scalar failed")
	}

	return c
}

// validateKey returns whether Y is of prime order.
func validateKey(Y *edwards25519.Point) bool {
	// Let Y' = cofactor*Y
	checkY := new(edwards25519.Point).MultByCofactor(Y)
	// If Y' is the identity element of the elliptic curve group, output "INVALID" and stop
	return checkY.Equal(identityPoint) != 1
}
