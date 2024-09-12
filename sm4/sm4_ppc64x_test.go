//go:build (ppc64 || ppc64le) && !purego

package sm4

import (
	"crypto/rand"
	"io"
	"reflect"
	"testing"
	"time"
)

func TestExpandKey(t *testing.T) {
	key := make([]byte, 16)

	var encRes1 [rounds]uint32
	var decRes1 [rounds]uint32
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
		expandKeyGo(key, &encRes1, &decRes1)
		expandKeyAsm(&key[0], &ck[0], &encRes2[0], &decRes2[0], 0)
		if !reflect.DeepEqual(encRes1[:], encRes2) {
			t.Errorf("expected=%x, result=%x\n", encRes1[:], encRes2)
		}
		if !reflect.DeepEqual(decRes1[:], decRes2) {
			t.Errorf("expected=%x, result=%x\n", decRes1[:], decRes2)
		}
	}
}

func TestEncryptBlockAsm(t *testing.T) {
	src := []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10}
	expected := []byte{0x68, 0x1e, 0xdf, 0x34, 0xd2, 0x06, 0x96, 0x5e, 0x86, 0xb3, 0xe9, 0x4f, 0x53, 0x6e, 0x42, 0x46}
	encRes2 := make([]uint32, 32)
	decRes2 := make([]uint32, 32)
	expandKeyAsm(&src[0], &ck[0], &encRes2[0], &decRes2[0], 0)
	dst := make([]byte, 16)
	encryptBlocksAsm(&encRes2[0], dst, src, 0)
	if !reflect.DeepEqual(dst, expected) {
		t.Errorf("expected=%x, result=%x\n", expected, dst)
	}
	encryptBlocksAsm(&decRes2[0], dst, expected, 0)
	if !reflect.DeepEqual(dst, src) {
		t.Errorf("expected=%x, result=%x\n", src, dst)
	}
}
