// Copyright 2018 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
//
//go:build !purego

#include "textflag.h"

// func xorBytes(dst, a, b *byte, n int)
TEXT ·xorBytes(SB), NOSPLIT, $0
	MOVQ  dst+0(FP), BX
	MOVQ  a+8(FP), SI
	MOVQ  b+16(FP), CX
	MOVQ  n+24(FP), DX
	CMPQ  DX, $32         // if len less than 32, non avx2.
	JL non_avx2
	CMPB ·useAVX2(SB), $1
	JE   avx2

non_avx2:
	TESTQ $15, DX            // AND 15 & len, if not zero jump to not_aligned.
	JNZ   not_aligned

aligned:
	MOVQ $0, AX // position in slices

loop16b:
	MOVOU (SI)(AX*1), X0   // XOR 16byte forwards.
	MOVOU (CX)(AX*1), X1
	PXOR  X1, X0
	MOVOU X0, (BX)(AX*1)
	ADDQ  $16, AX
	CMPQ  DX, AX
	JNE   loop16b
	RET

loop_1b:
	SUBQ  $1, DX           // XOR 1byte backwards.
	MOVB  (SI)(DX*1), DI
	MOVB  (CX)(DX*1), AX
	XORB  AX, DI
	MOVB  DI, (BX)(DX*1)
	TESTQ $7, DX           // AND 7 & len, if not zero jump to loop_1b.
	JNZ   loop_1b
	CMPQ  DX, $0           // if len is 0, ret.
	JE    ret
	TESTQ $15, DX          // AND 15 & len, if zero jump to aligned.
	JZ    aligned

not_aligned:
	TESTQ $7, DX           // AND $7 & len, if not zero jump to loop_1b.
	JNE   loop_1b
	SUBQ  $8, DX           // XOR 8bytes backwards.
	MOVQ  (SI)(DX*1), DI
	MOVQ  (CX)(DX*1), AX
	XORQ  AX, DI
	MOVQ  DI, (BX)(DX*1)
	CMPQ  DX, $16          // if len is greater or equal 16 here, it must be aligned.
	JGE   aligned

ret:
	RET

avx2:
	TESTQ $31, DX          // AND 31 & len, if not zero jump to avx2_not_aligned.
	JNZ   avx2_not_aligned

avx2_aligned:              // input length = 16*n, where n is greater or equal 2.
	TESTQ $16, DX          // AND 16 & len, if zero jump to loop32b_start.
	JE loop32b_start
	SUBQ  $16, DX          // XOR 16bytes backwards.
	VMOVDQU (SI)(DX*1), X0
	VPXOR  (CX)(DX*1), X0, X0
	VMOVDQU X0, (BX)(DX*1)

loop32b_start:
	MOVQ $0, AX            // position in slices

loop32b:
	VMOVDQU (SI)(AX*1), Y0   // XOR 32byte forwards.
	VPXOR (CX)(AX*1), Y0, Y0
	VMOVDQU Y0, (BX)(AX*1)
	ADDQ  $32, AX
	CMPQ  DX, AX
	JNE   loop32b

avx2_ret:	
	VZEROUPPER
	RET

avx2_loop_1b:
	SUBQ  $1, DX           // XOR 1byte backwards.
	MOVB  (SI)(DX*1), DI
	MOVB  (CX)(DX*1), AX
	XORB  AX, DI
	MOVB  DI, (BX)(DX*1)
	TESTQ $7, DX           // AND 7 & len, if not zero jump to avx2_loop_1b.
	JNZ   avx2_loop_1b
	TESTQ $15, DX          // AND 15 & len, if zero jump to aligned.
	JZ    avx2_aligned

avx2_not_aligned:
	TESTQ $7, DX           // AND $7 & len, if not zero jump to avx2_loop_1b.
	JNE   avx2_loop_1b
	TESTQ $8, DX           // AND $8 & len, if zero jump to avx2_aligned.
	JE   avx2_aligned
	SUBQ  $8, DX           // XOR 8bytes backwards.
	MOVQ  (SI)(DX*1), DI
	MOVQ  (CX)(DX*1), AX
	XORQ  AX, DI
	MOVQ  DI, (BX)(DX*1)
	JMP  avx2_aligned
