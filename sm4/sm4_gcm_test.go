//go:build amd64 || arm64
// +build amd64 arm64

package sm4

import (
	"fmt"
	"testing"
)

func TestPrecomputeTableAsm(t *testing.T) {
	key := []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10}
	c := sm4CipherAsm{sm4Cipher{make([]uint32, rounds), make([]uint32, rounds)}}
	expandKeyAsm(&key[0], &ck[0], &c.enc[0], &c.dec[0])
	c1 := &sm4CipherGCM{c}
	g := &gcmAsm{}
	g.cipher = &c1.sm4CipherAsm
	var key1 [gcmBlockSize]byte
	c1.Encrypt(key1[:], key1[:])
	fmt.Printf("%v\n", key1)
	precomputeTableAsm(&g.bytesProductTable, &key1)
	for i := 0; i < 16; i++ {
		for j := 0; j < 16; j++ {
			fmt.Printf("%02X ", g.bytesProductTable[i*16+j])
		}
		fmt.Println()
	}
}
