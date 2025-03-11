//go:build purego || !(amd64 || arm64 || ppc64 || ppc64le)

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
