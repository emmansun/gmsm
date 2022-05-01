#include "textflag.h"

#define B0 V0
#define B1 V1
#define B2 V2
#define B3 V3
#define B4 V4
#define B5 V5
#define B6 V6
#define B7 V7

#define ACC0 V8
#define ACC1 V9
#define ACCM V10

#define T0 V11
#define T1 V12
#define T2 V13
#define T3 V14

#define POLY V15
#define ZERO V16
#define INC V17
#define CTR V18

#define K0 V19
#define K1 V20
#define K2 V21
#define K3 V22
#define K4 V23
#define K5 V24
#define K6 V25
#define K7 V26

#define reduce() \
	VEOR	ACC0.B16, ACCM.B16, ACCM.B16     \
	VEOR	ACC1.B16, ACCM.B16, ACCM.B16     \
	VEXT	$8, ZERO.B16, ACCM.B16, T0.B16   \
	VEXT	$8, ACCM.B16, ZERO.B16, ACCM.B16 \
	VEOR	ACCM.B16, ACC0.B16, ACC0.B16     \
	VEOR	T0.B16, ACC1.B16, ACC1.B16       \
	VPMULL	POLY.D1, ACC0.D1, T0.Q1          \
	VEXT	$8, ACC0.B16, ACC0.B16, ACC0.B16 \
	VEOR	T0.B16, ACC0.B16, ACC0.B16       \
	VPMULL	POLY.D1, ACC0.D1, T0.Q1          \
	VEOR	T0.B16, ACC1.B16, ACC1.B16       \
	VEXT	$8, ACC1.B16, ACC1.B16, ACC1.B16 \
	VEOR	ACC1.B16, ACC0.B16, ACC0.B16     \

#define mulRound(X) \
	VLD1.P	32(pTbl), [T1.B16, T2.B16] \
	VREV64	X.B16, X.B16               \
	VEXT	$8, X.B16, X.B16, T0.B16   \
	VEOR	X.B16, T0.B16, T0.B16      \
	VPMULL	X.D1, T1.D1, T3.Q1         \
	VEOR	T3.B16, ACC1.B16, ACC1.B16 \
	VPMULL2	X.D2, T1.D2, T3.Q1         \
	VEOR	T3.B16, ACC0.B16, ACC0.B16 \
	VPMULL	T0.D1, T2.D1, T3.Q1        \
	VEOR	T3.B16, ACCM.B16, ACCM.B16

#define sm4eEnc1block() \
	WORD $0x6086c0ce         \ //SM4E V0.4S, V19.4S
	WORD $0x8086c0ce         \ //SM4E V0.4S, V20.4S
	WORD $0xa086c0ce         \ //SM4E V0.4S, V21.4S
	WORD $0xc086c0ce         \ //SM4E V0.4S, V22.4S
	WORD $0xe086c0ce         \ //SM4E V0.4S, V23.4S
	WORD $0x0087c0ce         \ //SM4E V0.4S, V24.4S
	WORD $0x2087c0ce         \ //SM4E V0.4S, V25.4S
	WORD $0x4087c0ce           //SM4E V0.4S, V26.4S

#define sm4eEnc8blocks() \
	sm4eEnc1block()         \
	WORD $0x6186c0ce         \ //SM4E V1.4S, V19.4S
	WORD $0x8186c0ce         \ //SM4E V1.4S, V20.4S
	WORD $0xa186c0ce         \ //SM4E V1.4S, V21.4S
	WORD $0xc186c0ce         \ //SM4E V1.4S, V22.4S
	WORD $0xe186c0ce         \ //SM4E V1.4S, V23.4S
	WORD $0x0187c0ce         \ //SM4E V1.4S, V24.4S
	WORD $0x2187c0ce         \ //SM4E V1.4S, V25.4S
	WORD $0x4187c0ce         \ //SM4E V1.4S, V26.4S
	WORD $0x6286c0ce         \ //SM4E V2.4S, V19.4S
	WORD $0x8286c0ce         \ //SM4E V2.4S, V20.4S
	WORD $0xa286c0ce         \ //SM4E V2.4S, V21.4S
	WORD $0xc286c0ce         \ //SM4E V2.4S, V22.4S
	WORD $0xe286c0ce         \ //SM4E V2.4S, V23.4S
	WORD $0x0287c0ce         \ //SM4E V2.4S, V24.4S
	WORD $0x2287c0ce         \ //SM4E V2.4S, V25.4S
	WORD $0x4287c0ce         \ //SM4E V2.4S, V26.4S
	WORD $0x6386c0ce         \ //SM4E V3.4S, V19.4S
	WORD $0x8386c0ce         \ //SM4E V3.4S, V20.4S
	WORD $0xa386c0ce         \ //SM4E V3.4S, V21.4S
	WORD $0xc386c0ce         \ //SM4E V3.4S, V22.4S
	WORD $0xe386c0ce         \ //SM4E V3.4S, V23.4S
	WORD $0x0387c0ce         \ //SM4E V3.4S, V24.4S
	WORD $0x2387c0ce         \ //SM4E V3.4S, V25.4S
	WORD $0x4387c0ce         \ //SM4E V3.4S, V26.4S
	WORD $0x6486c0ce         \ //SM4E V4.4S, V19.4S
	WORD $0x8486c0ce         \ //SM4E V4.4S, V20.4S
	WORD $0xa486c0ce         \ //SM4E V4.4S, V21.4S
	WORD $0xc486c0ce         \ //SM4E V4.4S, V22.4S
	WORD $0xe486c0ce         \ //SM4E V4.4S, V23.4S
	WORD $0x0487c0ce         \ //SM4E V4.4S, V24.4S
	WORD $0x2487c0ce         \ //SM4E V4.4S, V25.4S
	WORD $0x4487c0ce         \ //SM4E V4.4S, V26.4S
	WORD $0x6586c0ce         \ //SM4E V5.4S, V19.4S
	WORD $0x8586c0ce         \ //SM4E V5.4S, V20.4S
	WORD $0xa586c0ce         \ //SM4E V5.4S, V21.4S
	WORD $0xc586c0ce         \ //SM4E V5.4S, V22.4S
	WORD $0xe586c0ce         \ //SM4E V5.4S, V23.4S
	WORD $0x0587c0ce         \ //SM4E V5.4S, V24.4S
	WORD $0x2587c0ce         \ //SM4E V5.4S, V25.4S
	WORD $0x4587c0ce         \ //SM4E V5.4S, V26.4S
	WORD $0x6686c0ce         \ //SM4E V6.4S, V19.4S
	WORD $0x8686c0ce         \ //SM4E V6.4S, V20.4S
	WORD $0xa686c0ce         \ //SM4E V6.4S, V21.4S
	WORD $0xc686c0ce         \ //SM4E V6.4S, V22.4S
	WORD $0xe686c0ce         \ //SM4E V6.4S, V23.4S
	WORD $0x0687c0ce         \ //SM4E V6.4S, V24.4S
	WORD $0x2687c0ce         \ //SM4E V6.4S, V25.4S
	WORD $0x4687c0ce         \ //SM4E V6.4S, V26.4S
	WORD $0x6786c0ce         \ //SM4E V7.4S, V19.4S
	WORD $0x8786c0ce         \ //SM4E V7.4S, V20.4S
	WORD $0xa786c0ce         \ //SM4E V7.4S, V21.4S
	WORD $0xc786c0ce         \ //SM4E V7.4S, V22.4S
	WORD $0xe786c0ce         \ //SM4E V7.4S, V23.4S
	WORD $0x0787c0ce         \ //SM4E V7.4S, V24.4S
	WORD $0x2787c0ce         \ //SM4E V7.4S, V25.4S
	WORD $0x4787c0ce           //SM4E V7.4S, V26.4S    

// func gcmSm4niEnc(productTable *[256]byte, dst, src []byte, ctr, T *[16]byte, rk []uint32)
TEXT ·gcmSm4niEnc(SB),NOSPLIT,$0
#define pTbl R0
#define dstPtr R1
#define ctrPtr R2
#define srcPtr R3
#define rk R4
#define tPtr R5
#define srcPtrLen R6
#define aluCTR R7
#define aluTMP R8
#define H0 R9
#define H1 R10
#define pTblSave R11
#define rkSave R12
	MOVD	productTable+0(FP), pTbl
	MOVD	dst+8(FP), dstPtr
	MOVD	src_base+32(FP), srcPtr
	MOVD	src_len+40(FP), srcPtrLen
	MOVD	ctr+56(FP), ctrPtr
	MOVD	T+64(FP), tPtr
	MOVD	rk_base+72(FP), rk
	
	MOVD	$0xC2, H1
	LSL	$56, H1
	MOVD	$1, H0
	VMOV	H1, POLY.D[0]
	VMOV	H0, POLY.D[1]
	VEOR	ZERO.B16, ZERO.B16, ZERO.B16

	MOVD	pTbl, pTblSave
	// Current tag, after AAD
	VLD1	(tPtr), [ACC0.B16]
	VEOR	ACC1.B16, ACC1.B16, ACC1.B16
	VEOR	ACCM.B16, ACCM.B16, ACCM.B16
	// Prepare initial counter, and the increment vector
	VLD1	(ctrPtr), [CTR.B16]
	VEOR	INC.B16, INC.B16, INC.B16
	MOVD	$1, H0
	VMOV	H0, INC.S[3]
	VREV32	CTR.B16, CTR.B16
	VADD	CTR.S4, INC.S4, CTR.S4

	// Skip to <8 blocks loop
	CMP	$128, srcPtrLen

	MOVD	rk, H0
	// For SM4 round keys are stored in: K0 .. K7
	VLD1.P	64(H0), [K0.S4, K1.S4, K2.S4, K3.S4]
	VLD1.P	64(H0), [K4.S4, K5.S4, K6.S4, K7.S4]

	BLT	startSingles
octetsLoop:
		SUB	$128, srcPtrLen
		// Prepare 8 counters
		VMOV	CTR.B16, B0.B16
		VADD	B0.S4, INC.S4, B1.S4
		VADD	B1.S4, INC.S4, B2.S4
		VADD	B2.S4, INC.S4, B3.S4
		VADD	B3.S4, INC.S4, B4.S4
		VADD	B4.S4, INC.S4, B5.S4
		VADD	B5.S4, INC.S4, B6.S4
		VADD	B6.S4, INC.S4, B7.S4
		VADD	B7.S4, INC.S4, CTR.S4

		sm4eEnc8blocks()
		VREV32 B0.B16, B0.B16
		VREV32 B1.B16, B1.B16
		VREV32 B2.B16, B2.B16
		VREV32 B3.B16, B3.B16
		VREV32 B4.B16, B4.B16
		VREV32 B5.B16, B5.B16
		VREV32 B6.B16, B6.B16
		VREV32 B7.B16, B7.B16

		// XOR plaintext and store ciphertext
		VLD1.P	32(srcPtr), [T1.B16, T2.B16]
		VEOR	B0.B16, T1.B16, B0.B16
		VEOR	B1.B16, T2.B16, B1.B16
		VST1.P  [B0.B16, B1.B16], 32(dstPtr)
		VLD1.P	32(srcPtr), [T1.B16, T2.B16]
		VEOR	B2.B16, T1.B16, B2.B16
		VEOR	B3.B16, T2.B16, B3.B16
		VST1.P  [B2.B16, B3.B16], 32(dstPtr)
		VLD1.P	32(srcPtr), [T1.B16, T2.B16]
		VEOR	B4.B16, T1.B16, B4.B16
		VEOR	B5.B16, T2.B16, B5.B16
		VST1.P  [B4.B16, B5.B16], 32(dstPtr)
		VLD1.P	32(srcPtr), [T1.B16, T2.B16]
		VEOR	B6.B16, T1.B16, B6.B16
		VEOR	B7.B16, T2.B16, B7.B16
		VST1.P  [B6.B16, B7.B16], 32(dstPtr)

		VLD1.P	32(pTbl), [T1.B16, T2.B16]
		VREV64	B0.B16, B0.B16
		VEOR	ACC0.B16, B0.B16, B0.B16
		VEXT	$8, B0.B16, B0.B16, T0.B16
		VEOR	B0.B16, T0.B16, T0.B16
		VPMULL	B0.D1, T1.D1, ACC1.Q1
		VPMULL2	B0.D2, T1.D2, ACC0.Q1
		VPMULL	T0.D1, T2.D1, ACCM.Q1

		mulRound(B1)
		mulRound(B2)
		mulRound(B3)
		mulRound(B4)
		mulRound(B5)
		mulRound(B6)
		mulRound(B7)
		MOVD	pTblSave, pTbl
		reduce()

		CMP	$128, srcPtrLen
		BGE	octetsLoop

startSingles:
	CBZ	srcPtrLen, done
	ADD	$14*16, pTbl
	// Preload H and its Karatsuba precomp
	VLD1.P	(pTbl), [T1.B16, T2.B16]

singlesLoop:
		CMP	$16, srcPtrLen
		BLT	tail
		SUB	$16, srcPtrLen

		VMOV	CTR.B16, B0.B16
		VADD	CTR.S4, INC.S4, CTR.S4
		sm4eEnc1block()
		VREV32 B0.B16, B0.B16

singlesLast:
		VLD1.P	16(srcPtr), [T0.B16]
		VEOR	T0.B16, B0.B16, B0.B16

encReduce:
		VST1.P	[B0.B16], 16(dstPtr)

		VREV64	B0.B16, B0.B16
		VEOR	ACC0.B16, B0.B16, B0.B16

		VEXT	$8, B0.B16, B0.B16, T0.B16
		VEOR	B0.B16, T0.B16, T0.B16
		VPMULL	B0.D1, T1.D1, ACC1.Q1
		VPMULL2	B0.D2, T1.D2, ACC0.Q1
		VPMULL	T0.D1, T2.D1, ACCM.Q1

		reduce()

	B	singlesLoop
tail:
	CBZ	srcPtrLen, done

	VEOR	T0.B16, T0.B16, T0.B16
	VEOR	T3.B16, T3.B16, T3.B16
	MOVD	$0, H1
	SUB	$1, H1
	ADD	srcPtrLen, srcPtr

	TBZ	$3, srcPtrLen, ld4
	MOVD.W	-8(srcPtr), H0
	VMOV	H0, T0.D[0]
	VMOV	H1, T3.D[0]

ld4:
	TBZ	$2, srcPtrLen, ld2
	MOVW.W	-4(srcPtr), H0
	VEXT	$12, T0.B16, ZERO.B16, T0.B16
	VEXT	$12, T3.B16, ZERO.B16, T3.B16
	VMOV	H0, T0.S[0]
	VMOV	H1, T3.S[0]
ld2:
	TBZ	$1, srcPtrLen, ld1
	MOVH.W	-2(srcPtr), H0
	VEXT	$14, T0.B16, ZERO.B16, T0.B16
	VEXT	$14, T3.B16, ZERO.B16, T3.B16
	VMOV	H0, T0.H[0]
	VMOV	H1, T3.H[0]
ld1:
	TBZ	$0, srcPtrLen, ld0
	MOVB.W	-1(srcPtr), H0
	VEXT	$15, T0.B16, ZERO.B16, T0.B16
	VEXT	$15, T3.B16, ZERO.B16, T3.B16
	VMOV	H0, T0.B[0]
	VMOV	H1, T3.B[0]
ld0:
	MOVD	ZR, srcPtrLen
	VMOV	CTR.B16, B0.B16
	sm4eEnc1block()
	VREV32 B0.B16, B0.B16

tailLast:
	VEOR	T0.B16, B0.B16, B0.B16
	VAND	T3.B16, B0.B16, B0.B16
	B	encReduce

done:
	VST1	[ACC0.B16], (tPtr)
	RET

// func gcmSm4niDec(productTable *[256]byte, dst, src []byte, ctr, T *[16]byte, rk []uint32)
TEXT ·gcmSm4niDec(SB),NOSPLIT,$0
	MOVD	productTable+0(FP), pTbl
	MOVD	dst+8(FP), dstPtr
	MOVD	src_base+32(FP), srcPtr
	MOVD	src_len+40(FP), srcPtrLen
	MOVD	ctr+56(FP), ctrPtr
	MOVD	T+64(FP), tPtr
	MOVD	rk_base+72(FP), rk

	MOVD	$0xC2, H1
	LSL	$56, H1
	MOVD	$1, H0
	VMOV	H1, POLY.D[0]
	VMOV	H0, POLY.D[1]
	VEOR	ZERO.B16, ZERO.B16, ZERO.B16

	MOVD	pTbl, pTblSave
	MOVD rk, rkSave
	// Current tag, after AAD
	VLD1	(tPtr), [ACC0.B16]
	VEOR	ACC1.B16, ACC1.B16, ACC1.B16
	VEOR	ACCM.B16, ACCM.B16, ACCM.B16
	// Prepare initial counter, and the increment vector
	VLD1	(ctrPtr), [CTR.B16]
	VEOR	INC.B16, INC.B16, INC.B16
	MOVD	$1, H0
	VMOV	H0, INC.S[3]
	VREV32	CTR.B16, CTR.B16
	VADD	CTR.S4, INC.S4, CTR.S4

	// Skip to <8 blocks loop
	CMP	$128, srcPtrLen

	MOVD	rk, H0
	// For SM4 round keys are stored in: K0 .. K7
	VLD1.P	64(H0), [K0.S4, K1.S4, K2.S4, K3.S4]
	VLD1.P	64(H0), [K4.S4, K5.S4, K6.S4, K7.S4]

	BLT	startSingles
octetsLoop:
		SUB	$128, srcPtrLen

		VMOV	CTR.B16, B0.B16
		VADD	B0.S4, INC.S4, B1.S4
		VADD	B1.S4, INC.S4, B2.S4
		VADD	B2.S4, INC.S4, B3.S4
		VADD	B3.S4, INC.S4, B4.S4
		VADD	B4.S4, INC.S4, B5.S4
		VADD	B5.S4, INC.S4, B6.S4
		VADD	B6.S4, INC.S4, B7.S4
		VADD	B7.S4, INC.S4, CTR.S4

		sm4eEnc8blocks()      
		VREV32 B0.B16, T1.B16
		VREV32 B1.B16, T2.B16
		VREV32 B2.B16, B2.B16
		VREV32 B3.B16, B3.B16
		VREV32 B4.B16, B4.B16
		VREV32 B5.B16, B5.B16
		VREV32 B6.B16, B6.B16
		VREV32 B7.B16, B7.B16

		VLD1.P	32(srcPtr), [B0.B16, B1.B16]
		VEOR	B0.B16, T1.B16, T1.B16
		VEOR	B1.B16, T2.B16, T2.B16
		VST1.P  [T1.B16, T2.B16], 32(dstPtr)

		VLD1.P	32(pTbl), [T1.B16, T2.B16]
		VREV64	B0.B16, B0.B16
		VEOR	ACC0.B16, B0.B16, B0.B16
		VEXT	$8, B0.B16, B0.B16, T0.B16
		VEOR	B0.B16, T0.B16, T0.B16
		VPMULL	B0.D1, T1.D1, ACC1.Q1
		VPMULL2	B0.D2, T1.D2, ACC0.Q1
		VPMULL	T0.D1, T2.D1, ACCM.Q1
		mulRound(B1)

		VLD1.P	32(srcPtr), [B0.B16, B1.B16]
		VEOR	B2.B16, B0.B16, T1.B16
		VEOR	B3.B16, B1.B16, T2.B16
		VST1.P  [T1.B16, T2.B16], 32(dstPtr)
		mulRound(B0)
		mulRound(B1)

		VLD1.P	32(srcPtr), [B0.B16, B1.B16]
		VEOR	B4.B16, B0.B16, T1.B16
		VEOR	B5.B16, B1.B16, T2.B16
		VST1.P  [T1.B16, T2.B16], 32(dstPtr)
		mulRound(B0)
		mulRound(B1)

		VLD1.P	32(srcPtr), [B0.B16, B1.B16]
		VEOR	B6.B16, B0.B16, T1.B16
		VEOR	B7.B16, B1.B16, T2.B16
		VST1.P  [T1.B16, T2.B16], 32(dstPtr)
		mulRound(B0)
		mulRound(B1)

		MOVD	pTblSave, pTbl
		reduce()

		CMP	$128, srcPtrLen
		BGE	octetsLoop

startSingles:
	CBZ	srcPtrLen, done
	ADD	$14*16, pTbl
	// Preload H and its Karatsuba precomp
	VLD1.P	(pTbl), [T1.B16, T2.B16]

singlesLoop:
		CMP	$16, srcPtrLen
		BLT	tail
		SUB	$16, srcPtrLen

		VLD1.P	16(srcPtr), [T0.B16]
		VREV64	T0.B16, B5.B16

		VMOV	CTR.B16, B0.B16
		VADD	CTR.S4, INC.S4, CTR.S4
		sm4eEnc1block()
		VREV32 B0.B16, B0.B16

singlesLast:
		VEOR	T0.B16, B0.B16, B0.B16
		VST1.P	[B0.B16], 16(dstPtr)

		VEOR	ACC0.B16, B5.B16, B5.B16
		VEXT	$8, B5.B16, B5.B16, T0.B16
		VEOR	B5.B16, T0.B16, T0.B16
		VPMULL	B5.D1, T1.D1, ACC1.Q1
		VPMULL2	B5.D2, T1.D2, ACC0.Q1
		VPMULL	T0.D1, T2.D1, ACCM.Q1
		reduce()

	B	singlesLoop        
tail:
	CBZ	srcPtrLen, done
	VMOV	CTR.B16, B0.B16
	VADD	CTR.S4, INC.S4, CTR.S4
	sm4eEnc1block()
	VREV32 B0.B16, B0.B16    
tailLast:
	// Assuming it is safe to load past dstPtr due to the presence of the tag
	// B5 stored last ciphertext
	VLD1	(srcPtr), [B5.B16]

	VEOR	B5.B16, B0.B16, B0.B16

	VEOR	T3.B16, T3.B16, T3.B16
	MOVD	$0, H1
	SUB	$1, H1

	TBZ	$3, srcPtrLen, ld4 // Test if srcPtrLen < 8, if yes, goto ld4
	VMOV	B0.D[0], H0
	MOVD.P	H0, 8(dstPtr)
	VMOV	H1, T3.D[0]
	VEXT	$8, ZERO.B16, B0.B16, B0.B16
ld4:
	TBZ	$2, srcPtrLen, ld2 // Test if srcPtrLen < 4, if yes, goto ld2
	VMOV	B0.S[0], H0
	MOVW.P	H0, 4(dstPtr)
	VEXT	$12, T3.B16, ZERO.B16, T3.B16
	VMOV	H1, T3.S[0]
	VEXT	$4, ZERO.B16, B0.B16, B0.B16
ld2:
	TBZ	$1, srcPtrLen, ld1 // Test if srcPtrLen < 2, if yes, goto ld1
	VMOV	B0.H[0], H0
	MOVH.P	H0, 2(dstPtr)
	VEXT	$14, T3.B16, ZERO.B16, T3.B16
	VMOV	H1, T3.H[0]
	VEXT	$2, ZERO.B16, B0.B16, B0.B16
ld1:
	TBZ	$0, srcPtrLen, ld0 // Test if srcPtrLen < 1, if yes, goto ld0
	VMOV	B0.B[0], H0
	MOVB.P	H0, 1(dstPtr)
	VEXT	$15, T3.B16, ZERO.B16, T3.B16
	VMOV	H1, T3.B[0]
ld0:

	VAND	T3.B16, B5.B16, B5.B16
	VREV64	B5.B16, B5.B16

	VEOR	ACC0.B16, B5.B16, B5.B16
	VEXT	$8, B5.B16, B5.B16, T0.B16
	VEOR	B5.B16, T0.B16, T0.B16
	VPMULL	B5.D1, T1.D1, ACC1.Q1
	VPMULL2	B5.D2, T1.D2, ACC0.Q1
	VPMULL	T0.D1, T2.D1, ACCM.Q1
	reduce()
done:
	VST1	[ACC0.B16], (tPtr)

	RET
