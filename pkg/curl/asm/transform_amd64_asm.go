package main

import (
	"fmt"

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
	if (curl.StateSize-1)%blockSize != 0 {
		panic(fmt.Sprintf("invalid unroll: %d", unroll))
	}

	a := bct{"a", GP64(), GP64()}
	src.Load(0, a)
	b := bct{"b", GP64(), GP64()}
	src.Load(364, b)
	sBox(&a, b)
	dst.Store(a, 0)

	t := namedRegister{GP64(), "t"}
	MOVQ(U32(364), t)

	i := namedRegister{GP64(), "i"}
	MOVQ(U32(1), i)

	Label("StateLoop")
	for u := 0; u < blockSize; u += 2 {
		src.LoadIdx(t, 364-u/2, a)
		sBox(&b, a)
		dst.StoreIdx(b, i, u)

		src.LoadIdx(t, -1-u/2, b)
		sBox(&a, b)
		dst.StoreIdx(a, i, u+1)
	}
	SUBQ(U32(unroll), t)

	// loop through the entire state
	ADDQ(U32(blockSize), i)
	CMPQ(i, U32(curl.StateSize))
	JL(LabelRef("StateLoop"))
}

// sBox sets a to sBox(a, b).
func sBox(a *bct, b bct) {
	Commentf("%s = sBox(%s, %s)", a, a, b)
	// a.h = (b.l ^ a.h) & a.l
	XORQ(b.l, a.h)
	ANDQ(a.l, a.h)
	// a.l = (b.h ^ a.l) | a.h
	XORQ(b.h, a.l)
	ORQ(a.h, a.l)
	// a.h = ^a.h
	NOTQ(a.h)

	a.l, a.h = a.h, a.l
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
