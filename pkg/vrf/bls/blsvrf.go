package bls

import (
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/pairing/bn256"
	"go.dedis.ch/kyber/v3/sign/bdn"
	"golang.org/x/crypto/blake2b"
)

type PrivateKey = kyber.Scalar
type PublicKey = kyber.Point

var suite = bn256.NewSuite()

func GenerateKey() (PublicKey, PrivateKey) {
	s, P := bdn.NewKeyPair(suite, suite.RandomStream())

	return P, s
}

type Proof []byte

func (p Proof) Hash() []byte {
	betaString := blake2b.Sum512(p)

	return betaString[:]
}

func (p Proof) Bytes() []byte {
	return p
}

func Prove(privateKey PrivateKey, alphaString []byte) Proof {
	proof, err := bdn.Sign(suite, privateKey, alphaString)
	if err != nil {
		panic(err)
	}

	return proof
}

func ProofToHash(piString []byte) ([]byte, error) {
	return Proof(piString).Hash(), nil
}

func Verify(publicKey PublicKey, alphaString []byte, piString []byte) (bool, []byte) {
	if bdn.Verify(suite, publicKey, alphaString, piString) != nil {
		return false, nil
	}

	return true, Proof(piString).Bytes()
}
