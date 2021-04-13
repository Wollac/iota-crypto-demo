package curl

func transformGeneric(lto, hto, lfrom, hfrom *[StateSize]uint) {
	for r := NumRounds; r > 0; r-- {
		aL, aH := lfrom[0], hfrom[0]
		bL, bH := lfrom[364], hfrom[364]
		lto[0], hto[0] = sBox(aL, aH, bL, bH)

		t := 364
		for i := 1; i <= StateSize-4; i += 4 {
			t += 364
			aL, aH = lfrom[t], hfrom[t]
			lto[i+0], hto[i+0] = sBox(bL, bH, aL, aH)

			t -= 365
			bL, bH = lfrom[t], hfrom[t]
			lto[i+1], hto[i+1] = sBox(aL, aH, bL, bH)

			t += 364
			aL, aH = lfrom[t], hfrom[t]
			lto[i+2], hto[i+2] = sBox(bL, bH, aL, aH)

			t -= 365
			bL, bH = lfrom[t], hfrom[t]
			lto[i+3], hto[i+3] = sBox(aL, aH, bL, bH)
		}
		// swap buffers
		lfrom, lto = lto, lfrom
		hfrom, hto = hto, hfrom
	}
}

func sBox(aL, aH, bL, bH uint) (uint, uint) {
	tmp := aL & (aH ^ bL)
	return ^tmp, (aL ^ bH) | tmp
}
