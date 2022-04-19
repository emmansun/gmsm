package zuc

import (
	"testing"
)

func Test_genKeyword_case1(t *testing.T) {
	s, _ := newZUCState([]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0})
	z1 := s.genKeyword()
	if z1 != 0x27bede74 {
		t.Errorf("expected=%x, result=%x\n", 0x27bede74, z1)
	}
	z2 := s.genKeyword()
	if z2 != 0x018082da {
		t.Errorf("expected=%x, result=%x\n", 0x018082da, z2)
	}
}

func Test_genKeyword_case2(t *testing.T) {
	s, _ := newZUCState([]byte{255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255}, []byte{255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255})
	z1 := s.genKeyword()
	if z1 != 0x0657cfa0 {
		t.Errorf("expected=%x, result=%x\n", 0x0657cfa0, z1)
	}
	z2 := s.genKeyword()
	if z2 != 0x7096398b {
		t.Errorf("expected=%x, result=%x\n", 0x7096398b, z2)
	}
}

func Test_genKeyword_case3(t *testing.T) {
	s, _ := newZUCState([]byte{0x3d, 0x4c, 0x4b, 0xe9, 0x6a, 0x82, 0xfd, 0xae, 0xb5, 0x8f, 0x64, 0x1d, 0xb1, 0x7b, 0x45, 0x5b}, []byte{0x84, 0x31, 0x9a, 0xa8, 0xde, 0x69, 0x15, 0xca, 0x1f, 0x6b, 0xda, 0x6b, 0xfb, 0xd8, 0xc7, 0x66})
	z1 := s.genKeyword()
	if z1 != 0x14f1c272 {
		t.Errorf("expected=%x, result=%x\n", 0x14f1c272, z1)
	}
	z2 := s.genKeyword()
	if z2 != 0x3279c419 {
		t.Errorf("expected=%x, result=%x\n", 0x3279c419, z2)
	}
}
