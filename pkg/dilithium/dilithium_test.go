package dilithium

import (
	"math/rand"
	"testing"

	"github.com/cloudflare/circl/sign/eddilithium2"
)

const MessageSize = 128

func BenchmarkSign(b *testing.B) {
	_, sk, err := eddilithium2.GenerateKey(nil)
	if err != nil {
		b.Fatal(err)
	}
	data := make([][MessageSize]byte, b.N)
	for i := range data {
		rand.Read(data[i][:])
	}

	b.ResetTimer()
	for i := range data {
		var sig [eddilithium2.SignatureSize]byte
		eddilithium2.SignTo(sk, data[i][:], sig[:])
	}
}

func BenchmarkVerify(b *testing.B) {
	pk, sk, err := eddilithium2.GenerateKey(nil)
	if err != nil {
		b.Fatal(err)
	}
	data := make([]struct {
		message []byte
		sig     [eddilithium2.SignatureSize]byte
	}, b.N)
	for i := range data {
		data[i].message = make([]byte, MessageSize)
		rand.Read(data[i].message)
		eddilithium2.SignTo(sk, data[i].message, data[i].sig[:])
	}

	b.ResetTimer()
	for i := range data {
		if !eddilithium2.Verify(pk, data[i].message, data[i].sig[:]) {
			b.Fail()
		}
	}
}
