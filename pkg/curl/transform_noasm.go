// +build !amd64 !gc purego

package curl

func transform(lto, hto, lfrom, hfrom *[StateSize]uint) {
	transformGeneric(lto, hto, lfrom, hfrom)
}
