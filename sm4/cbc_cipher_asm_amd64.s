//go:build amd64 && !generic
// +build amd64,!generic

#include "textflag.h"

#define x X0
#define y X1
#define t0 X2
#define t1 X3
#define t2 X4
#define t3 X5

#define XTMP6 X6
#define IV X8

#include "aesni_amd64.h"

#define SM4_SINGLE_ROUND(index, RK, IND, x, y, z, t0, t1, t2, t3)  \ 
	PINSRD $0, (index * 4)(RK)(IND*1), x;             \
	PXOR t1, x;                                       \
	PXOR t2, x;                                       \
	PXOR t3, x;                                       \
	SM4_TAO_L1(x, y, z);                              \
	PXOR x, t0

// func encryptBlocksChain(xk *uint32, dst, src []byte, iv *byte)
TEXT ·encryptBlocksChain(SB),NOSPLIT,$0
#define ctx BX
#define ptx DX
#define ptxLen DI

	MOVQ xk+0(FP), AX
	MOVQ dst+8(FP), ctx
	MOVQ src+32(FP), ptx
	MOVQ src_len+40(FP), ptxLen
	MOVQ iv+56(FP), SI

	MOVUPS (SI), IV

loopSrc:
		CMPQ ptxLen, $16
		JB done_sm4
		SUBQ $16, ptxLen

		MOVUPS (ptx), t0
		PXOR IV, t0

		PSHUFB flip_mask<>(SB), t0
		PSHUFD $1, t0, t1
		PSHUFD $2, t0, t2
		PSHUFD $3, t0, t3

		XORL CX, CX

loopRound:
			SM4_SINGLE_ROUND(0, AX, CX, x, y, XTMP6, t0, t1, t2, t3)
			SM4_SINGLE_ROUND(1, AX, CX, x, y, XTMP6, t1, t2, t3, t0)
			SM4_SINGLE_ROUND(2, AX, CX, x, y, XTMP6, t2, t3, t0, t1)
			SM4_SINGLE_ROUND(3, AX, CX, x, y, XTMP6, t3, t0, t1, t2)

			ADDL $16, CX
			CMPL CX, $4*32
			JB loopRound

		PEXTRD $0, t2, R8
		PINSRD $1, R8, t3
		PEXTRD $0, t1, R8
		PINSRD $2, R8, t3
		PEXTRD $0, t0, R8
		PINSRD $3, R8, t3
		PSHUFB flip_mask<>(SB), t3

		MOVOU t3, IV
		MOVUPS t3, (ctx)

		LEAQ 16(ptx), ptx
		LEAQ 16(ctx), ctx
	
		JMP loopSrc

done_sm4:
	MOVUPS IV, (SI)
	RET

#undef ctx
#undef ptx
#undef ptxLen
