// Copyright 2026 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build riscv64 && go1.27 && !purego

#include "textflag.h"

// XTS mode fused with the Zvksed extension, mirroring xts_sm4ni_arm64.s for
// arm64 and driven by sm4ni_xts.go. The tweak is kept in vector registers and
// doubled with RVV ops; the SM4 rounds use vsm4r.vs with a 2-block (E32, M2)
// main loop, following the conventions of asm_zvksed_riscv64.s:
//   - round keys are plain 32-bit words loaded with vle32;
//   - blocks are byte-swapped with vrev8 before/after the rounds;
//   - the store reverses the word order via the ·riscv64ZvksedRev index.
//
// The tweak update of each path matches the generic implementation in
// internal/cipher/xts: the encrypt path and the plain last-block decrypt path
// advance the tweak, while the ciphertext-stealing paths leave the tweak that
// was used for the final full block.
//
// Preconditions enforced by the Go dispatch (validateXtsInput in modes.go and
// newCipher in cipher_asm.go):
//   - the Zvksed extension is available (sm4.NewCipher returns the NI cipher
//     only when supportSM4 is true);
//   - VLEN >= 128, so that VSETIVLI $8, E32, M2 and VSETIVLI $16, E8, M1
//     set the full vl (the same assumption the other zvksed asm makes);
//   - src contains at least one complete XTS block (len >= 16);
//   - dst and src overlap exactly or not at all.

// VSM4R_VS performs vsm4r.vs Vd, Vs2
// OP-P(0x77) | funct6=101001,vm=1 → 0x53 | vs2[24:20] | vs1=10000 | funct3=010 | vd
#define VSM4R_VS(Vd, Vs2) \
	WORD $((0x53 << 25) | ((Vs2) << 20) | (0x10 << 15) | (2 << 12) | ((Vd) << 7) | 0x77)

#define ZERO X0
#define xkPtr X10
#define dstPtr X11
#define srcPtr X12
#define srcLen X13
#define tmpPtr X14
#define twPtr X15
#define gbFlag X16
#define polyC X17
#define t0 X18
#define t1 X19

#define BSTATE V4  // block state: M2 group (V4-V5) in the main loop, M1 elsewhere
#define BREV   V6  // word-reversed copy: M2 group (V6-V7) or M1
#define K0 V8
#define K1 V10
#define K2 V12
#define K3 V14
#define K4 V16
#define K5 V18
#define K6 V20
#define K7 V22
#define RIDX V24 // reversal index: M2 group (V24-V25); M1 views use [3,2,1,0]
#define TW0 V26  // current tweak (M1); with TW1 it forms the M2 group [TW0, TW1]
#define TW1 V27  // TW0 * 2 in GF(2^128)
#define TT0 V28  // doubling scratch
#define TT1 V29  // doubling scratch

// DST = SRC * 2 in GF(2^128), polynomial x^128 + x^7 + x^2 + x + 1.
// Requires vtype E32, M1, vl=4; clobbers TT0/TT1.
#define MUL2_TW(SRC, DST) \
	VSLLVI $1, SRC, DST; \
	VSRLVI $31, SRC, TT0; \
	VSLIDE1UPVX ZERO, TT0, TT1; \
	VORVV DST, TT1, DST; \
	VSRAVI $31, SRC, TT0; \
	VSLIDEDOWNVI $3, TT0, TT1; \
	VANDVX polyC, TT1, TT1; \
	VXORVV DST, TT1, DST

// DST = SRC * 2 following GB/T 17964-2021 (byte-wise view).
// Requires vtype E8, M1, vl=16; clobbers TT0/TT1.
#define MUL2_GB(SRC, DST) \
	VSLLVI $7, SRC, DST; \
	VSLIDE1UPVX ZERO, DST, TT0; \
	VSRLVI $1, SRC, TT1; \
	VORVV TT1, TT0, TT1; \
	VSLIDEDOWNVI $15, DST, TT0; \
	VSRAVI $7, TT0, TT0; \
	VANDVX polyC, TT0, TT0; \
	VXORVV TT1, TT0, DST

#define SM4ROUNDS() \
	VSM4R_VS(4, 8); \
	VSM4R_VS(4, 10); \
	VSM4R_VS(4, 12); \
	VSM4R_VS(4, 14); \
	VSM4R_VS(4, 16); \
	VSM4R_VS(4, 18); \
	VSM4R_VS(4, 20); \
	VSM4R_VS(4, 22)

// func encryptSm4NiXts(xk *uint32, tweak *[BlockSize]byte, dst, src []byte, isGB bool)
TEXT ·encryptSm4NiXts(SB), NOSPLIT, $0
	MOV	xk+0(FP), xkPtr
	MOV	tweak+8(FP), twPtr
	MOV	dst_base+16(FP), dstPtr
	MOV	src_base+40(FP), srcPtr
	MOV	src_len+48(FP), srcLen
	MOVBU	isGB+64(FP), gbFlag

	MOV	$0x87, polyC
	BEQ	gbFlag, ZERO, encPoly
	MOV	$0xE1, polyC
encPoly:

	VSETIVLI	$4, E32, M1, TA, MA, X0

	// round keys
	VLE32V	(xkPtr), K0
	ADD	$16, xkPtr, tmpPtr
	VLE32V	(tmpPtr), K1
	ADD	$16, tmpPtr
	VLE32V	(tmpPtr), K2
	ADD	$16, tmpPtr
	VLE32V	(tmpPtr), K3
	ADD	$16, tmpPtr
	VLE32V	(tmpPtr), K4
	ADD	$16, tmpPtr
	VLE32V	(tmpPtr), K5
	ADD	$16, tmpPtr
	VLE32V	(tmpPtr), K6
	ADD	$16, tmpPtr
	VLE32V	(tmpPtr), K7

	// current tweak
	VLE32V	(twPtr), TW0

	// element reversal index (loop invariant)
	VSETIVLI	$8, E32, M2, TA, MA, X0
	MOV	$·riscv64ZvksedRev(SB), tmpPtr
	VLE32V	(tmpPtr), RIDX

	// TW1 = TW0 * 2, needed by the first main loop pass
	BNE	gbFlag, ZERO, encInitGB
	VSETIVLI	$4, E32, M1, TA, MA, X0
	MUL2_TW(TW0, TW1)
	JMP	encInitDone
encInitGB:
	VSETIVLI	$16, E8, M1, TA, MA, X0
	MUL2_GB(TW0, TW1)
encInitDone:

	MOV	$32, xkPtr
enc2loop:
	BLT	srcLen, xkPtr, encSingles
	SUB	$32, srcLen

	VSETIVLI	$8, E32, M2, TA, MA, X0
	VLE32V	(srcPtr), BSTATE
	ADD	$32, srcPtr
	VREV8V	BSTATE, BSTATE
	VXORVV	TW0, BSTATE, BSTATE
	SM4ROUNDS()
	VREV8V	BSTATE, BSTATE
	VRGATHERVV	RIDX, BSTATE, BREV
	VXORVV	TW0, BREV, BREV
	VSE32V	BREV, (dstPtr)
	ADD	$32, dstPtr

	// Advance by two blocks:
	//   before: TW0 = T[n],   TW1 = T[n+1]
	//   after:  TW0 = T[n+2], TW1 = T[n+3]
	BNE	gbFlag, ZERO, enc2MulGB
	VSETIVLI	$4, E32, M1, TA, MA, X0
	MUL2_TW(TW1, TW0)
	MUL2_TW(TW0, TW1)
	JMP	enc2MulDone
enc2MulGB:
	VSETIVLI	$16, E8, M1, TA, MA, X0
	MUL2_GB(TW1, TW0)
	MUL2_GB(TW0, TW1)
enc2MulDone:
	JMP	enc2loop

encSingles:
	MOV	$16, xkPtr
	BEQ	srcLen, ZERO, encDone
enc1loop:
	BLT	srcLen, xkPtr, encTail
	SUB	$16, srcLen

	VSETIVLI	$4, E32, M1, TA, MA, X0
	VLE32V	(srcPtr), BSTATE
	ADD	$16, srcPtr
	VREV8V	BSTATE, BSTATE
	VXORVV	TW0, BSTATE, BSTATE
	SM4ROUNDS()
	VREV8V	BSTATE, BSTATE
	VXORVV	TW0, BSTATE, BSTATE
	VRGATHERVV	RIDX, BSTATE, BREV
	VSE32V	BREV, (dstPtr)
	ADD	$16, dstPtr

	// TW0 <- TW1, TW1 = TW0 * 2
	VMVVV	TW1, TW0
	BNE	gbFlag, ZERO, enc1MulGB
	VSETIVLI	$4, E32, M1, TA, MA, X0
	MUL2_TW(TW0, TW1)
	JMP	enc1MulDone
enc1MulGB:
	VSETIVLI	$16, E8, M1, TA, MA, X0
	MUL2_GB(TW0, TW1)
enc1MulDone:
	JMP	enc1loop

encTail:
	// ciphertext stealing: 0 < srcLen < 16
	SUB	$16, dstPtr, tmpPtr
	VSETIVLI	$16, E8, M1, TA, MA, X0
	VLE8V	(tmpPtr), V0
	VSETVLI	srcLen, E8, M1, TA, MA, X0
	VLE8V	(srcPtr), V1
	VSE8V	V0, (dstPtr)
	VSE8V	V1, (tmpPtr)

	VSETIVLI	$4, E32, M1, TA, MA, X0
	VLE32V	(tmpPtr), BSTATE
	VREV8V	BSTATE, BSTATE
	VXORVV	TW0, BSTATE, BSTATE
	SM4ROUNDS()
	VREV8V	BSTATE, BSTATE
	VXORVV	TW0, BSTATE, BSTATE
	VRGATHERVV	RIDX, BSTATE, BREV
	VSE32V	BREV, (tmpPtr)

encDone:
	VSETIVLI	$4, E32, M1, TA, MA, X0
	VSE32V	TW0, (twPtr)
	RET

// func decryptSm4NiXts(xk *uint32, tweak *[BlockSize]byte, dst, src []byte, isGB bool)
TEXT ·decryptSm4NiXts(SB), NOSPLIT, $0
	MOV	xk+0(FP), xkPtr
	MOV	tweak+8(FP), twPtr
	MOV	dst_base+16(FP), dstPtr
	MOV	src_base+40(FP), srcPtr
	MOV	src_len+48(FP), srcLen
	MOVBU	isGB+64(FP), gbFlag

	MOV	$0x87, polyC
	BEQ	gbFlag, ZERO, decPoly
	MOV	$0xE1, polyC
decPoly:

	VSETIVLI	$4, E32, M1, TA, MA, X0

	// round keys
	VLE32V	(xkPtr), K0
	ADD	$16, xkPtr, tmpPtr
	VLE32V	(tmpPtr), K1
	ADD	$16, tmpPtr
	VLE32V	(tmpPtr), K2
	ADD	$16, tmpPtr
	VLE32V	(tmpPtr), K3
	ADD	$16, tmpPtr
	VLE32V	(tmpPtr), K4
	ADD	$16, tmpPtr
	VLE32V	(tmpPtr), K5
	ADD	$16, tmpPtr
	VLE32V	(tmpPtr), K6
	ADD	$16, tmpPtr
	VLE32V	(tmpPtr), K7

	// current tweak
	VLE32V	(twPtr), TW0

	// element reversal index (loop invariant)
	VSETIVLI	$8, E32, M2, TA, MA, X0
	MOV	$·riscv64ZvksedRev(SB), tmpPtr
	VLE32V	(tmpPtr), RIDX

	// TW1 = TW0 * 2, needed by the first main loop pass
	BNE	gbFlag, ZERO, decInitGB
	VSETIVLI	$4, E32, M1, TA, MA, X0
	MUL2_TW(TW0, TW1)
	JMP	decInitDone
decInitGB:
	VSETIVLI	$16, E8, M1, TA, MA, X0
	MUL2_GB(TW0, TW1)
decInitDone:

	MOV	$48, xkPtr
dec2loop:
	BLT	srcLen, xkPtr, decSingles
	SUB	$32, srcLen

	VSETIVLI	$8, E32, M2, TA, MA, X0
	VLE32V	(srcPtr), BSTATE
	ADD	$32, srcPtr
	VREV8V	BSTATE, BSTATE
	VXORVV	TW0, BSTATE, BSTATE
	SM4ROUNDS()
	VREV8V	BSTATE, BSTATE
	VRGATHERVV	RIDX, BSTATE, BREV
	VXORVV	TW0, BREV, BREV
	VSE32V	BREV, (dstPtr)
	ADD	$32, dstPtr

	// Advance by two blocks:
	//   before: TW0 = T[n],   TW1 = T[n+1]
	//   after:  TW0 = T[n+2], TW1 = T[n+3]
	BNE	gbFlag, ZERO, dec2MulGB
	VSETIVLI	$4, E32, M1, TA, MA, X0
	MUL2_TW(TW1, TW0)
	MUL2_TW(TW0, TW1)
	JMP	dec2MulDone
dec2MulGB:
	VSETIVLI	$16, E8, M1, TA, MA, X0
	MUL2_GB(TW1, TW0)
	MUL2_GB(TW0, TW1)
dec2MulDone:
	JMP	dec2loop

decSingles:
	// one full block at a time while at least two blocks remain, so the
	// leftover is always 16 or 16 + t bytes for the tail paths below
	MOV	$32, xkPtr
dec1loop:
	BLT	srcLen, xkPtr, decTailSel
	SUB	$16, srcLen

	VSETIVLI	$4, E32, M1, TA, MA, X0
	VLE32V	(srcPtr), BSTATE
	ADD	$16, srcPtr
	VREV8V	BSTATE, BSTATE
	VXORVV	TW0, BSTATE, BSTATE
	SM4ROUNDS()
	VREV8V	BSTATE, BSTATE
	VXORVV	TW0, BSTATE, BSTATE
	VRGATHERVV	RIDX, BSTATE, BREV
	VSE32V	BREV, (dstPtr)
	ADD	$16, dstPtr

	// TW0 <- TW1, TW1 = TW0 * 2
	VMVVV	TW1, TW0
	BNE	gbFlag, ZERO, dec1MulGB
	VSETIVLI	$4, E32, M1, TA, MA, X0
	MUL2_TW(TW0, TW1)
	JMP	dec1MulDone
dec1MulGB:
	VSETIVLI	$16, E8, M1, TA, MA, X0
	MUL2_GB(TW0, TW1)
dec1MulDone:
	JMP	dec1loop

decTailSel:
	BEQ	srcLen, ZERO, decDone
	MOV	$16, t0
	BEQ	srcLen, t0, decLast
	JMP	decCTS

decLast:
	// exactly one full block left; decrypt it with TW0
	VSETIVLI	$4, E32, M1, TA, MA, X0
	VLE32V	(srcPtr), BSTATE
	VREV8V	BSTATE, BSTATE
	VXORVV	TW0, BSTATE, BSTATE
	SM4ROUNDS()
	VREV8V	BSTATE, BSTATE
	VXORVV	TW0, BSTATE, BSTATE
	VRGATHERVV	RIDX, BSTATE, BREV
	VSE32V	BREV, (dstPtr)

	// advance the tweak; TW1 already holds TW0 * 2
	VMVVV	TW1, TW0
	JMP	decDone

decCTS:
	// srcLen = 16 + t with 0 < t < 16; TW1 holds TW0 * 2.
	// 1. Decrypt the stolen block (the first 16 bytes) with TW1.
	VSETIVLI	$4, E32, M1, TA, MA, X0
	VLE32V	(srcPtr), BSTATE
	VREV8V	BSTATE, BSTATE
	VXORVV	TW1, BSTATE, BSTATE
	SM4ROUNDS()
	VREV8V	BSTATE, BSTATE
	VXORVV	TW1, BSTATE, BSTATE
	ADD	$16, srcPtr
	VRGATHERVV	RIDX, BSTATE, BREV
	VSE32V	BREV, (dstPtr)

	// 2. Output PP[:t] as the partial plaintext and rebuild:
	//
	//    CC = C_tail || PP[t:]
	//
	// BREV holds PP in normal memory byte order; dst[t:16] already
	// contains PP[t:] from the full-block store above.
	SUB	$16, srcLen, t0
	VSETVLI	t0, E8, M1, TA, MA, X0
	VLE8V	(srcPtr), V0 // ciphertext tail, read before any overwrite
	ADD	$16, dstPtr, t1
	VSE8V	BREV, (t1) // partial plaintext = PP[:t]
	VSE8V	V0, (dstPtr) // ciphertext tail over the stolen prefix

	// 3. Decrypt the rebuilt block in place with TW0.
	VSETIVLI	$4, E32, M1, TA, MA, X0
	VLE32V	(dstPtr), BSTATE
	VREV8V	BSTATE, BSTATE
	VXORVV	TW0, BSTATE, BSTATE
	SM4ROUNDS()
	VREV8V	BSTATE, BSTATE
	VXORVV	TW0, BSTATE, BSTATE
	VRGATHERVV	RIDX, BSTATE, BREV
	VSE32V	BREV, (dstPtr)

decDone:
	VSETIVLI	$4, E32, M1, TA, MA, X0
	VSE32V	TW0, (twPtr)
	RET
