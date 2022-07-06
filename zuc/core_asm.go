//go:build (amd64 && !generic) || (arm64 && !generic)
// +build amd64,!generic arm64,!generic

package zuc

import (
	"golang.org/x/sys/cpu"
)

var supportsAES = cpu.X86.HasAES
var useAVX = cpu.X86.HasAVX

//go:noescape
func genKeywordAsm(s *zucState32) uint32

//go:noescape
func genKeyStreamAsm(keyStream []uint32, pState *zucState32)

func genKeyStream(keyStream []uint32, pState *zucState32) {
	if supportsAES {
		genKeyStreamAsm(keyStream, pState)
		return
	}
	for i := 0; i < len(keyStream); i++ {
		keyStream[i] = genKeyword(pState)
	}
}

func genKeyword(s *zucState32) uint32 {
	if supportsAES {
		return genKeywordAsm(s)
	}
	s.bitReorganization()
	z := s.x3 ^ s.f32()
	s.enterWorkMode()
	return z
}
