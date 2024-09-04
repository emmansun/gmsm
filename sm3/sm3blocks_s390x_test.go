//go:build s390x && !purego

package sm3

import (
	"fmt"
	"testing"
)

func TestTransposeMatrix(t *testing.T) {
	var m [4][8]uint32
	var k uint32 = 0
	for i := 0; i < 4; i++ {
		for j := 0; j < 8; j++ {
			m[i][j] = k
			k++
			fmt.Printf("%04x ", m[i][j])
		}
		fmt.Println()
	}
	input := [4]*[8]uint32{&m[0], &m[1], &m[2], &m[3]}
	transposeMatrix(&input[0])
	fmt.Println()
	fmt.Println()
	for i := 0; i < 4; i++ {
		for j := 0; j < 8; j++ {
			fmt.Printf("%04x ", m[i][j])
		}
		fmt.Println()
	}
}

func TestCopyResultsBy4(t *testing.T) {
	var m [4][8]uint32
	var k uint32 = 0
	for i := 0; i < 4; i++ {
		for j := 0; j < 8; j++ {
			m[i][j] = k << 24
			k++
			fmt.Printf("%04x ", m[i][j])
		}
		fmt.Println()
	}
	var p [128]byte
	copyResultsBy4(&m[0][0], &p[0])
	fmt.Println()
	fmt.Println()
	for i := 0; i < 128; i++ {
		fmt.Printf("%02x ", p[i])
		if i%16 == 15 {
			fmt.Println()
		}
	}
}
