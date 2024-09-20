
// Copyright 2016 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build !purego

#include "textflag.h"

// func ghash(key *gcmHashKey, hash *[16]byte, data []byte)
TEXT ·ghash(SB),NOSPLIT,$32-40
	MOVD    $65, R0 // GHASH function code
	MOVD	key+0(FP), R2
	LMG	(R2), R6, R7
	MOVD	hash+8(FP), R8
	LMG	(R8), R4, R5
	MOVD	$params-32(SP), R1
	STMG	R4, R7, (R1)
	LMG	data+16(FP), R2, R3 // R2=base, R3=len
loop:
	WORD    $0xB93E0002 // compute intermediate message digest (KIMD)
	BVS     loop        // branch back if interrupted
	MVC     $16, (R1), (R8)
	MOVD	$0, R0
	RET
