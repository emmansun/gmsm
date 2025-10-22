// Copyright 2025 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

package sm3

import (
	"fmt"
	"testing"

	"github.com/emmansun/gmsm/internal/byteorder"
)

func TestBlocktest(t *testing.T) {
	data := make([]byte, 64)
	data[0] = 'a'
	data[1] = 'b'
	data[2] = 'c'
	data[3] = 0x80
	data[63] = 0x18

	d := New()
	d1, _ := d.(*digest)
	block(d1, data)
	var digest [Size]byte

	byteorder.BEPutUint32(digest[0:], d1.h[0])
	byteorder.BEPutUint32(digest[4:], d1.h[1])
	byteorder.BEPutUint32(digest[8:], d1.h[2])
	byteorder.BEPutUint32(digest[12:], d1.h[3])
	byteorder.BEPutUint32(digest[16:], d1.h[4])
	byteorder.BEPutUint32(digest[20:], d1.h[5])
	byteorder.BEPutUint32(digest[24:], d1.h[6])
	byteorder.BEPutUint32(digest[28:], d1.h[7])
	if fmt.Sprintf("%x", digest) != "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0" {
		t.Fatalf("sm3 block failed, got %x", digest)
	}
}
