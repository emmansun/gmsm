//go:build !purego

package sm3


//go:noescape
func transposeMatrix8x8(dig **[8]uint32)
