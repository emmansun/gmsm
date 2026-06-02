// Copyright 2026 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build !purego

#include "textflag.h"

// shuffle byte order from LE to BE
DATA flip_mask<>+0x00(SB)/8, $0x0405060700010203
DATA flip_mask<>+0x08(SB)/8, $0x0c0d0e0f08090a0b
GLOBL flip_mask<>(SB), RODATA, $16

#define VEX_Rp(x)  (1 - ((x) >> 3))
#define VEX_Bp(x)  (1 - ((x) >> 3))
#define VEX_VVVV(x) (15 - (x))
#define MODRM_REG3(x) (((x) & 7) << 3)
#define MODRM_RM3(x)  ((x) & 7)

// VSM3MSG1 xmm1, xmm2, xmm3
#define VSM3MSG1(Xd, Xs1, Xs2) \
	BYTE $0xC4; \
	BYTE $((0x42) | (VEX_Rp(Xd) << 7) | (VEX_Bp(Xs2) << 5)); \
	BYTE $((0x00) | (VEX_VVVV(Xs1) << 3)); \
	BYTE $0xDA; \
	BYTE $((0xC0) | MODRM_RM3(Xs2) | MODRM_REG3(Xd))

// VSM3MSG2 xmm1, xmm2, xmm3
#define VSM3MSG2(Xd, Xs1, Xs2) \
	BYTE $0xC4; \
	BYTE $((0x42) | (VEX_Rp(Xd) << 7) | (VEX_Bp(Xs2) << 5)); \
	BYTE $((0x01) | (VEX_VVVV(Xs1) << 3)); \
	BYTE $0xDA; \
	BYTE $((0xC0) | MODRM_RM3(Xs2) | MODRM_REG3(Xd))

// VSM3RNDS2 xmm1, xmm2, xmm3, imm8
#define VSM3RNDS2(Xd, Xs1, Xs2, IMM8) \
	BYTE $0xC4; \
	BYTE $((0x43) | (VEX_Rp(Xd) << 7) | (VEX_Bp(Xs2) << 5)); \
	BYTE $((0x01) | (VEX_VVVV(Xs1) << 3)); \
	BYTE $0xDE; \
	BYTE $((0xC0) | MODRM_REG3(Xd) | MODRM_RM3(Xs2)); \
	BYTE $((IMM8) & 0xFF)

#define SM3MSG(out, x0, x1, x2, x3, iout, i0) \
	VPALIGNR $12, x1, x2, out; \  // out = [w7, w8, w9, w10]
	VPSRLDQ $4, x3, X7;        \  // X7 = [w13, w14, w15, 0]
	VSM3MSG1(iout, 7, i0);     \ 
	VPALIGNR $12, x0, x1, X7;  \  // X7 = [w3, w4, w5, w6]
	VPALIGNR $8, x2, x3, X8;   \  // X8 = [w10, w11, w12, w13]
	VSM3MSG2(iout, 7, 8)	

#define SM3RNDS4(x0, x4, imm8) \
	VPUNPCKLQDQ x4, x0, X7;        \
	VSM3RNDS2(1, 0, 7, imm8);      \
	VPUNPCKHQDQ x4, x0, X7;        \
	VSM3RNDS2(0, 1, 7, (imm8+2))

#define NUM_BYTES DX
#define INP	DI

#define CTX SI // Beginning of digest in memory (a, b, c, ... , h)

#define BYTE_FLIP_MASK 	X13 // mask to convert LE -> BE

// func blockSM3NI(dig *digest, p []byte)
TEXT ·blockSM3NI(SB),NOSPLIT,$0
	MOVQ dig+0(FP), CTX          // d.h[8]
	MOVQ p_base+8(FP), INP
	MOVQ p_len+16(FP), NUM_BYTES

	SHRQ $6, NUM_BYTES
	SHLQ $6, NUM_BYTES

	LEAQ (INP)(NUM_BYTES*1), AX
	CMPQ INP, AX
	JEQ end

	VMOVDQU flip_mask<>(SB), BYTE_FLIP_MASK
	// load state
	VMOVDQU (CTX), X1      // X1 = [A, B, C, D]
	VMOVDQU 16(CTX), X2    // X2 = [E, F, G, H]
	VPSHUFD $0xB1, X1, X1  // X1 = [B, A, D, C]
	VPSHUFD $0xB1, X2, X2  // X2 = [F, E, H, G]
	VPUNPCKLQDQ X1, X2, X0 // X0 = [F, E, B, A]
	VPUNPCKHQDQ X1, X2, X1 // X1 = [H, G, D, C]
	VPSRLD $9, X1, X2
	VPSLLD $23, X1, X3
	VPOR X2, X3, X2        // X2 = ROR32(HGDC, 9)
	VPSRLD $19, X1, X3
	VPSLLD $13, X1, X4
	VPOR X3, X4, X3        // X3 = ROR32(HGDC, 19)
	VPBLENDD $3, X3, X2, X1 // X1 = [ROR32(H, 19), ROR32(G, 19), ROR32(D, 9), ROR32(D, 9)]

loop:
	// save state for next iteration
	VMOVDQU X0, X10
	VMOVDQU X1, X11
	// load message block
	VMOVDQU (INP), X2
	VMOVDQU 16(INP), X3
	VMOVDQU 32(INP), X4
	VMOVDQU 48(INP), X5
	// convert message block from LE to BE
	VPSHUFB BYTE_FLIP_MASK, X2, X2  // X2 = [w0, w1, w2, w3] in BE
	VPSHUFB BYTE_FLIP_MASK, X3, X3  // X3 = [w4, w5, w6, w7] in BE
	VPSHUFB BYTE_FLIP_MASK, X4, X4  // X4 = [w8, w9, w10, w11] in BE
	VPSHUFB BYTE_FLIP_MASK, X5, X5  // X5 = [w12, w13, w14, w15] in BE

	// message schedule & compress
	SM3MSG(X6, X2, X3, X4, X5, 6, 2)
	SM3RNDS4(X2, X3, 0)

	SM3MSG(X2, X3, X4, X5, X6, 2, 3)
	SM3RNDS4(X3, X4, 4)
	
	SM3MSG(X3, X4, X5, X6, X2, 3, 4)
	SM3RNDS4(X4, X5, 8)
	
	SM3MSG(X4, X5, X6, X2, X3, 4, 5)
	SM3RNDS4(X5, X6, 12)
	
	SM3MSG(X5, X6, X2, X3, X4, 5, 6)
	SM3RNDS4(X6, X2, 16)
	
	SM3MSG(X6, X2, X3, X4, X5, 6, 2)
	SM3RNDS4(X2, X3, 20)
	
	SM3MSG(X2, X3, X4, X5, X6, 2, 3)
	SM3RNDS4(X3, X4, 24)
	
	SM3MSG(X3, X4, X5, X6, X2, 3, 4)
	SM3RNDS4(X4, X5, 28)
	
	SM3MSG(X4, X5, X6, X2, X3, 4, 5)
	SM3RNDS4(X5, X6, 32)
	
	SM3MSG(X5, X6, X2, X3, X4, 5, 6)
	SM3RNDS4(X6, X2, 36)
	
	SM3MSG(X6, X2, X3, X4, X5, 6, 2)
	SM3RNDS4(X2, X3, 40)
	
	SM3MSG(X2, X3, X4, X5, X6, 2, 3)
	SM3RNDS4(X3, X4, 44)
	
	SM3MSG(X3, X4, X5, X6, X2, 3, 4)
	SM3RNDS4(X4, X5, 48)
	
	SM3RNDS4(X5, X6, 52)
	SM3RNDS4(X6, X2, 56)
	SM3RNDS4(X2, X3, 60)

	// update state
	VPXOR X10, X0, X0
	VPXOR X11, X1, X1

	LEAQ 64(INP), INP
	CMPQ INP, AX
	JNE loop

end:
	// store state
	VPSLLD $9, X1, X2
	VPSRLD $23, X1, X3
	VPXOR X2, X3, X2        // X2 = ROL32(HGDC, 9)
	VPSLLD $19, X1, X3
	VPSRLD $13, X1, X4
	VPXOR X3, X4, X3        // X3 = ROL32(HGDC, 19)
	VPBLENDD $3, X3, X2, X1 // X1 = [ROL32(H, 19), ROL32(G, 19), ROL32(D, 9), ROL32(D, 9)]
	VPSHUFD $0xB1, X0, X0
	VPSHUFD $0xB1, X1, X1
	VPUNPCKHQDQ X1, X0, X2
	VPUNPCKLQDQ X1, X0, X3

	VMOVDQU X2, (CTX)
	VMOVDQU X3, 16(CTX)

	RET
