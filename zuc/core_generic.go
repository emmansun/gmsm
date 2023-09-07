//go:build (!amd64 && !arm64) || purego || plugin
// +build !amd64,!arm64 purego plugin

package zuc

func genKeyStream(keyStream []uint32, pState *zucState32) {
	for i := 0; i < len(keyStream); i++ {
		keyStream[i] = pState.genKeyword()
	}
}

func genKeyword(s *zucState32) uint32 {
	s.bitReorganization()
	z := s.x3 ^ s.f32()
	s.enterWorkMode()
	return z
}
