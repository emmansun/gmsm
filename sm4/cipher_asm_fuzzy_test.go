//go:build amd64 || arm64
// +build amd64 arm64

package sm4

import (
	"fmt"
	"testing"
)

/*
func TestExpandKey(t *testing.T) {
	key := make([]byte, 16)

	encRes1 := make([]uint32, 32)
	decRes1 := make([]uint32, 32)
	encRes2 := make([]uint32, 32)
	decRes2 := make([]uint32, 32)
	var timeout *time.Timer

	if testing.Short() {
		timeout = time.NewTimer(10 * time.Millisecond)
	} else {
		timeout = time.NewTimer(2 * time.Second)
	}

	for {
		select {
		case <-timeout.C:
			return
		default:
		}
		io.ReadFull(rand.Reader, key)
		expandKeyGo(key, encRes1, decRes1)
		expandKeyAsm(&key[0], &ck[0], &encRes2[0], &decRes2[0])
		if !reflect.DeepEqual(encRes1, encRes2) {
			t.Errorf("expected=%v, result=%v\n", encRes1, encRes2)
		}
		if !reflect.DeepEqual(decRes1, decRes2) {
			t.Errorf("expected=%v, result=%v\n", encRes1, encRes2)
		}
	}
}
*/

func TestExpandKeySimple(t *testing.T) {
	key := []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10}

	encRes1 := make([]uint32, 32)
	decRes1 := make([]uint32, 32)
	encRes2 := make([]uint32, 32)
	decRes2 := make([]uint32, 32)

	expandKeyGo(key, encRes1, decRes1)
	expandKeyAsm(&key[0], &ck[0], &encRes2[0], &decRes2[0])
	fmt.Printf("expected=%v, result=%v\n", encRes1, encRes2)
	fmt.Printf("expected=%v, result=%v\n", decRes1, decRes2)
}

