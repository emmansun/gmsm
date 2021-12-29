//go:build amd64
// +build amd64

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
			t.Fatalf("expected=%v, result=%v\n", encRes1, encRes2)
		}
		if !reflect.DeepEqual(decRes1, decRes2) {
			t.Fatalf("expected=%v, result=%v\n", encRes1, encRes2)
		}
	}
}
