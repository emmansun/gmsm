//go:build (amd64 || arm64 || ppc64 || ppc64le) && !purego

package zuc

import (
	"github.com/emmansun/gmsm/internal/cpuid"
	"golang.org/x/sys/cpu"
)

// Generate single keyword, 4 bytes.
//
//go:noescape
func genKeywordAsm(s *zucState32) uint32

// Generate multiple keywords, n*4 bytes.
//
//go:noescape
func genKeyStreamAsm(keyStream []uint32, pState *zucState32)

var supportsAES = cpuid.HasAES
var useAVX = cpu.X86.HasAVX

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
