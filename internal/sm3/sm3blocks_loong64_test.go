//go:build loong64 && !purego

package sm3

import "testing"

func TestTransposeMatrix8x8(t *testing.T) {
	if !supportLSX {
		t.Skip("LSX is not supported")
	}
	var m [8][8]uint32
	for i := 0; i < 8; i++ {
		for j := 0; j < 8; j++ {
			m[i][j] = uint32(i*8 + j)
		}
	}
	input := [8]*[8]uint32{&m[0], &m[1], &m[2], &m[3], &m[4], &m[5], &m[6], &m[7]}
	transposeMatrix8x8(&input[0])
	for i := 0; i < 8; i++ {
		for j := 0; j < 8; j++ {
			if m[j][i] != uint32(i*8+j) {
				t.Errorf("m[%d][%d] got %d", i, j, m[j][i])
			}
		}
	}
	transposeMatrix8x8(&input[0])
	for i := 0; i < 8; i++ {
		for j := 0; j < 8; j++ {
			if m[i][j] != uint32(i*8+j) {
				t.Errorf("m[%d][%d] got %d", i, j, m[i][j])
			}
		}
	}
}
