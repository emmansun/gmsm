// Copyright 2026 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build loong64 && !purego

#include "textflag.h"
#include "sm4_macros_loong64.s"

// func encryptSm4Ecb(xk *uint32, dst, src []byte)
// ECB encryption: processes src_len bytes (always a multiple of 16).
// Same LASX 8-block path as encryptBlocksAsm; scalar fallback for remaining blocks.
TEXT ·encryptSm4Ecb(SB), NOSPLIT, $0-56
	MOVV xk+0(FP), R4
	MOVV dst_base+8(FP), R5
	MOVV src_base+32(FP), R6
	MOVV src_len+40(FP), R7

	// LASX path
	MOVV $128, R8
	BLTU R7, R8, ecb_scalar_path

	// Load sbox into X0-X15 (16 bytes each, replicated to both 128-bit lanes).
	MOVV $·sbox(SB), R9
	VMOVQ 0(R9), V0;   XVPERMIQ_REPL(0)
	VMOVQ 16(R9), V8;  XVPERMIQ_REPL(8)
	VMOVQ 32(R9), V1;  XVPERMIQ_REPL(1)
	VMOVQ 48(R9), V9;  XVPERMIQ_REPL(9)
	VMOVQ 64(R9), V2;  XVPERMIQ_REPL(2)
	VMOVQ 80(R9), V10; XVPERMIQ_REPL(10)
	VMOVQ 96(R9), V3;  XVPERMIQ_REPL(3)
	VMOVQ 112(R9), V11; XVPERMIQ_REPL(11)
	VMOVQ 128(R9), V4;  XVPERMIQ_REPL(4)
	VMOVQ 144(R9), V12; XVPERMIQ_REPL(12)
	VMOVQ 160(R9), V5;  XVPERMIQ_REPL(5)
	VMOVQ 176(R9), V13; XVPERMIQ_REPL(13)
	VMOVQ 192(R9), V6;  XVPERMIQ_REPL(6)
	VMOVQ 208(R9), V14; XVPERMIQ_REPL(14)
	VMOVQ 224(R9), V7;  XVPERMIQ_REPL(7)
	VMOVQ 240(R9), V15; XVPERMIQ_REPL(15)

	MOVV $0x01, R9; XVMOVQ R9, X20.B32
	MOVV $0x80, R9; XVMOVQ R9, X21.B32
	MOVV $0x1F, R9; XVMOVQ R9, X22.B32

ecb_lasx_loop:
	XVMOVQ 0(R6), X23;  XVMOVQ 32(R6), X24
	XVMOVQ 64(R6), X25; XVMOVQ 96(R6), X26
	XVSHUF4IB $0x1B, X23, X23; XVSHUF4IB $0x1B, X24, X24
	XVSHUF4IB $0x1B, X25, X25; XVSHUF4IB $0x1B, X26, X26
	XVILVLW X23, X24, X27; XVILVHW X23, X24, X28
	XVILVLW X25, X26, X29; XVILVHW X25, X26, X30
	XVILVLV X27, X29, X16; XVILVHV X27, X29, X17
	XVILVLV X28, X30, X18; XVILVHV X28, X30, X19
	MOVV R4, R11; MOVV $8, R12
ecb_round_loop:
	LASX_4ROUNDS()
	ADDV $-1, R12
	BNE R12, R0, ecb_round_loop
	XVILVLW X19, X18, X27; XVILVHW X19, X18, X28
	XVILVLW X17, X16, X29; XVILVHW X17, X16, X30
	XVILVLV X30, X28, X23; XVILVHV X30, X28, X24
	XVILVLV X29, X27, X25; XVILVHV X29, X27, X26
	XVSHUF4IB $0x1B, X23, X23; XVSHUF4IB $0x1B, X24, X24
	XVSHUF4IB $0x1B, X25, X25; XVSHUF4IB $0x1B, X26, X26
	XVMOVQ X23, 0(R5);  XVMOVQ X24, 32(R5)
	XVMOVQ X25, 64(R5); XVMOVQ X26, 96(R5)
	ADDV $128, R5; ADDV $128, R6; ADDV $-128, R7
	BGEU R7, R8, ecb_lasx_loop

ecb_scalar_path:
	MOVV $·sbox_t0(SB), ST0
	MOVV $·sbox_t1(SB), ST1
	MOVV $·sbox_t2(SB), ST2
	MOVV $·sbox_t3(SB), ST3

ecb_loop:
	BEQ R7, R0, ecb_done
	ENCRYPT_BLOCK()
	ADDV $16, R5
	ADDV $16, R6
	ADDV $-16, R7
	JMP ecb_loop

ecb_done:
	RET
