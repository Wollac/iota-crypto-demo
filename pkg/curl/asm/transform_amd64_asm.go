package main

import (
	. "github.com/mmcloughlin/avo/build"
	. "github.com/mmcloughlin/avo/operand"
	. "github.com/mmcloughlin/avo/reg"
	"github.com/wollac/iota-crypto-demo/pkg/curl"
)

const unroll = 2

//go:generate go run transform_amd64_asm.go -out ../transform_amd64.s -stubs ../transform_amd64.go -pkg curl

func main() {
	Package("github.com/wollac/iota-crypto-demo/pkg/curl")
	ConstraintExpr("amd64,gc,!purego")
	transform()
	Generate()
}

func transform() {
	TEXT("transform", NOSPLIT, "func(lto, hto, lfrom, hfrom *[StateSize]uint)")
	Doc("transform transforms the sponge state. It works like transformGeneric.")
	Pragma("noescape")

	to := bctMem{
		name: "to",
		l:    Mem{Base: Load(Param("lto"), GP64())},
		h:    Mem{Base: Load(Param("hto"), GP64())},
	}
	from := bctMem{
		name: "from",
		l:    Mem{Base: Load(Param("lfrom"), GP64())},
		h:    Mem{Base: Load(Param("hfrom"), GP64())},
	}

	r := GP64()
	MOVQ(U32(curl.NumRounds), r)

	Label("RoundLoop")

	stateLoop(from, to)

	Comment("swap buffers")
	XCHGQ(from.l.Base, to.l.Base)
	XCHGQ(from.h.Base, to.h.Base)

	DECQ(r)
	JNZ(LabelRef("RoundLoop"))

	RET()
}

func stateLoop(src, dst bctMem) {
	blockSize := 2 * unroll
	// the number of unrolled iterations must be even (as sBox swaps high and low)
	// and the state size must be divisible by the unrolled block
	if (curl.StateSize-1)%blockSize != 0 {
		panic("invalid unroll")
	}

	a := bct{"a", GP64(), GP64()}
	src.Load(0, a)
	b := bct{"b", GP64(), GP64()}
	src.Load(364, b)
	dst.Store(sBox(a, b), 0)

	t := namedRegister{GP64(), "t"}
	MOVQ(U32(364), t)

	i := namedRegister{GP64(), "i"}
	MOVQ(U32(1), i)

	Label("StateLoop")
	offset := 0
	for u := 0; u < blockSize; u += 2 {
		offset += 364
		src.LoadIdx(t, offset, a)
		dst.StoreIdx(sBox(b, a), i, u)

		offset -= 365
		src.LoadIdx(t, offset, b)
		dst.StoreIdx(sBox(a, b), i, u+1)
	}
	SUBQ(U32(-offset), t)

	// loop through the entire state
	ADDQ(U32(blockSize), i)
	CMPQ(i, U32(curl.StateSize))
	JL(LabelRef("StateLoop"))
}

// sBox returns sBox(a, b).
// The content of a and b is not modified.
func sBox(a bct, b bct) bct {
	s := bct{"s", GP64(), GP64()}
	Commentf("%s = sBox(%s, %s)", s, a, b)
	// s.l = (b.l ^ a.h) & a.l
	MOVQ(b.l, s.l)
	XORQ(a.h, s.l)
	ANDQ(a.l, s.l)
	// s.h = (a.l ^ b.h) | s.l
	MOVQ(a.l, s.h)
	XORQ(b.h, s.h)
	ORQ(s.l, s.h)
	// s.l = ^s.l
	NOTQ(s.l)
	return s
}

type namedRegister struct {
	Register
	name string
}

func (r namedRegister) String() string { return r.name }

type bct struct {
	name string
	l, h GPVirtual
}

func (b bct) String() string { return b.name }

type bctMem struct {
	name string
	l, h Mem
}

func (m bctMem) String() string { return m.name }

func (m bctMem) Load(offset int, dst bct) {
	Commentf("%s = %s[%d]", dst, m, offset)
	MOVQ(m.l.Offset(offset*8), dst.l)
	MOVQ(m.h.Offset(offset*8), dst.h)
}

func (m bctMem) LoadIdx(index namedRegister, offset int, dst bct) {
	Commentf("%s = %s[%d+%s]", dst, m, offset, index)
	MOVQ(m.l.Idx(index, 8).Offset(offset*8), dst.l)
	MOVQ(m.h.Idx(index, 8).Offset(offset*8), dst.h)
}

func (m bctMem) Store(src bct, offset int) {
	Commentf("%s[%d] = %s", m, offset, src)
	MOVQ(src.l, m.l.Offset(offset*8))
	MOVQ(src.h, m.h.Offset(offset*8))
}

func (m bctMem) StoreIdx(src bct, index namedRegister, offset int) {
	Commentf("%s[%d+%s] = %s", m, offset, index, src)
	MOVQ(src.l, m.l.Idx(index, 8).Offset(offset*8))
	MOVQ(src.h, m.h.Idx(index, 8).Offset(offset*8))
}
