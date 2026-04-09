// Copyright 2026 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build !purego

#include "textflag.h"

// nttMulNEON computes out[i] = fieldMul(lhs[i], rhs[i]) for i in [0, 255].
TEXT ·nttMulNEON(SB), NOSPLIT, $0-24
	MOVD lhs+0(FP), R0
	MOVD rhs+8(FP), R1
	MOVD out+16(FP), R2
	MOVD $32, R3

	// pinned
	MOVD $8380417, R8
	VDUP R8, V31.S4
	MOVD $4236238847, R8
	VDUP R8, V30.S4
    MOVD $32, R4
loop:

	VLD1.P (32)(R0), [V0.S4, V1.S4]   // lhs
	VLD1.P (32)(R1), [V2.S4, V3.S4]   // rhs

    // step 1: V0 * V2
    WORD $0x4ea29c14                  // MUL   V20.4S, V0.4S, V2.4S
    WORD $0x4ebe9e96                  // MUL   V22.4S, V20.4S, V30.4S
    WORD $0x6ea2b415                  // SQRDMULH V21.4S, V0.4S, V2.4S (hi' = Round(2*hi))
    WORD $0x6ebfb6d7                  // SQRDMULH V23.4S, V22.4S, V31.4S (corr' = Round(2*corr))
    VADD V21.S4, V23.S4, V20.S4       // raw = 2*Result
    WORD $0x4f3f0694                  // VSSHR V20.S4, V20.S4, #1
    WORD $0x4f210698                  // VSSHR V24.S4, V20.S4, #31
	VAND V31.B16, V24.B16, V24.B16    // q if underflow, else 0
	VADD V20.S4, V24.S4, V4.S4        // result in V4

    // step 1: V1 * V3
    WORD $0x4ea39c34                  // MUL   V20.4S, V1.4S, V3.4S
    WORD $0x4ebe9e96                  // MUL   V22.4S, V20.4S, V30.4S
    WORD $0x6ea3b434                  // SQRDMULH V21.4S, V1.4S, V3.4S (hi' = Round(2*hi))
    WORD $0x6ebfb6d7                  // SQRDMULH V23.4S, V22.4S, V31.4S (corr' = Round(2*corr))
    VADD V21.S4, V23.S4, V20.S4       // raw = 2*Result
    WORD $0x4f3f0694                  // VSSHR V20.S4, V20.S4, #1
    WORD $0x4f210698                  // VSSHR V24.S4, V20.S4, #31
	VAND V31.B16, V24.B16, V24.B16    // q if underflow, else 0
	VADD V20.S4, V24.S4, V5.S4        // result in V5

    VST1.P [V4.S4, V5.S4], (32)(R2)
	SUBS $1, R4, R4
	BNE loop

done:
	RET
