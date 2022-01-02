//go:build amd64 || arm64
// +build amd64 arm64

package sm4

import (
	"fmt"
	"testing"
)

func TestPrecomputeTableAsm(t *testing.T) {
	key := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}
	c := sm4CipherAsm{sm4Cipher{make([]uint32, rounds), make([]uint32, rounds)}}
	expandKeyAsm(&key[0], &ck[0], &c.enc[0], &c.dec[0])
	c1 := &sm4CipherGCM{c}
	g := &gcmAsm{}
	g.cipher = &c1.sm4CipherAsm
	var key1 [gcmBlockSize]byte
	c1.Encrypt(key1[:], key1[:])
	precomputeTableAsm(&g.bytesProductTable, &key1)
	fmt.Printf("%v\n", g.bytesProductTable)
}
