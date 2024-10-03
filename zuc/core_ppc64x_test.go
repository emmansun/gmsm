// Copyright 2024 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build (ppc64 || ppc64le) && !purego

package zuc

import "testing"

func Test_genKeywordAsm_case1(t *testing.T) {
	s, _ := newZUCState([]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0})
	z1 := genKeywordAsm(s)
	if z1 != 0x27bede74 {
		t.Errorf("expected=%x, result=%x\n", 0x27bede74, z1)
	}
	if s.r1 != 0xc7ee7f13 {
		t.Errorf("expected=%x, result=%x\n", 0xc7ee7f13, s.r1)
	}
	if s.r2 != 0xc0fa817 {
		t.Errorf("expected=%x, result=%x\n", 0xc0fa817, s.r2)
	}	
	z2 := genKeywordAsm(s)
	if z2 != 0x018082da {
		t.Errorf("expected=%x, result=%x\n", 0x018082da, z2)
	}
}
