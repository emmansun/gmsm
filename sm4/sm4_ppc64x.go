//go:build (ppc64 || ppc64le) && !purego

package sm4

//go:noescape
func encryptBlocksAsm(xk *uint32, dst, src []byte, inst int)

//go:noescape
func encryptBlockAsm(xk *uint32, dst, src *byte, inst int)

//go:noescape
func expandKeyAsm(key *byte, ck, enc, dec *uint32, inst int)
