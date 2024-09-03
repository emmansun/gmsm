//go:build s390x && !purego

package sm3

import (
	"fmt"
	"testing"
)

func TestTransposeMatrix(t *testing.T) {
	var m [4][8]uint32
	for i := 0; i < 4; i++ {
		for j := 0; j < 8; j++ {
			m[i][j] = uint32(i*4 + j)
			fmt.Printf("%04x ", m[i][j])
		}
		fmt.Println()
	}
	input := [4]*[8]uint32{&m[0], &m[1], &m[2], &m[3]}
	transposeMatrix(&input[0])
	for i := 0; i < 4; i++ {
		for j := 0; j < 8; j++ {
			m[i][j] = uint32(i*4 + j)
			fmt.Printf("%04x ", m[i][j])
		}
		fmt.Println()
	}
}
