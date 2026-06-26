#define avxMul2GBInline        \
	VPSHUFB BSWAP, TW, TW;       \
	\// TW * 2
	VPSLLQ $63, TW, T0;     \      
 	VPSHUFD $0, TW, T1;     \
	VPSRLQ $1, TW, TW;      \
	VPSRLDQ $8, T0, T0;     \
	VPOR T0, TW, TW;        \
	\// reduction
	VPSLLD $31, T1, T1;     \
	VPSRAD $31, T1, T1;     \
	VPAND POLY, T1, T1;     \
	VPXOR T1, TW, TW;       \
	VPSHUFB BSWAP, TW, TW

#define avxPrepareGB4Tweaks \
	VMOVDQU TW, (16*0)(SP); \
	avxMul2GBInline;           \ 
	VMOVDQU TW, (16*1)(SP); \ 
	avxMul2GBInline;           \
	VMOVDQU TW, (16*2)(SP); \
	avxMul2GBInline;           \
	VMOVDQU TW, (16*3)(SP); \
	avxMul2GBInline

#define avxPrepareGB8Tweaks \
	avxPrepareGB4Tweaks;       \
	VMOVDQU TW, (16*4)(SP); \
	avxMul2GBInline;           \
	VMOVDQU TW, (16*5)(SP); \
	avxMul2GBInline;           \
	VMOVDQU TW, (16*6)(SP); \
	avxMul2GBInline;           \
	VMOVDQU TW, (16*7)(SP); \
	avxMul2GBInline

#define avxPrepareGB16Tweaks \
	avxPrepareGB8Tweaks;       \
	VMOVDQU TW, (16*8)(SP); \
	avxMul2GBInline;           \
	VMOVDQU TW, (16*9)(SP); \
	avxMul2GBInline;           \
	VMOVDQU TW, (16*10)(SP); \
	avxMul2GBInline;           \
	VMOVDQU TW, (16*11)(SP); \
	avxMul2GBInline;           \
	VMOVDQU TW, (16*12)(SP); \
	avxMul2GBInline;           \
	VMOVDQU TW, (16*13)(SP); \
	avxMul2GBInline;           \
	VMOVDQU TW, (16*14)(SP); \
	avxMul2GBInline;           \
	VMOVDQU TW, (16*15)(SP); \
	avxMul2GBInline

#define avxMul2Inline        \
	VPSHUFD $0xff, TW, T0; \
	VPSRLD $31, TW, T1;    \       
	VPSRAD $31, T0, T0;    \
	VPAND POLY, T0, T0;    \        
	VPSLLDQ $4, T1, T1;    \
	VPSLLD $1, TW, TW;     \
	VPXOR T0, TW, TW;      \
	VPXOR T1, TW, TW

#define avxPrepare4Tweaks \
	VMOVDQU TW, (16*0)(SP); \
	avxMul2Inline;           \ 
	VMOVDQU TW, (16*1)(SP); \ 
	avxMul2Inline;           \
	VMOVDQU TW, (16*2)(SP); \
	avxMul2Inline;           \
	VMOVDQU TW, (16*3)(SP); \
	avxMul2Inline

#define avxPrepare8Tweaks \
	avxPrepare4Tweaks;       \
	VMOVDQU TW, (16*4)(SP); \
	avxMul2Inline;           \
	VMOVDQU TW, (16*5)(SP); \
	avxMul2Inline;           \
	VMOVDQU TW, (16*6)(SP); \
	avxMul2Inline;           \
	VMOVDQU TW, (16*7)(SP); \
	avxMul2Inline

#define avxPrepare16Tweaks \
	prepare8Tweaks;       \
	VMOVDQU TW, (16*8)(SP); \
	avxMul2Inline;           \
	VMOVDQU TW, (16*9)(SP); \
	avxMul2Inline;           \
	VMOVDQU TW, (16*10)(SP); \
	avxMul2Inline;           \
	VMOVDQU TW, (16*11)(SP); \
	avxMul2Inline;           \
	VMOVDQU TW, (16*12)(SP); \
	avxMul2Inline;           \
	VMOVDQU TW, (16*13)(SP); \
	avxMul2Inline;           \
	VMOVDQU TW, (16*14)(SP); \
	avxMul2Inline;           \
	VMOVDQU TW, (16*15)(SP); \
	avxMul2Inline

#define avxLoad4Blocks \
	VMOVDQU (16*0)(DX), B0; \
	VPXOR (16*0)(SP), B0, B0; \
	VMOVDQU (16*1)(DX), B1; \
	VPXOR (16*1)(SP), B1, B1; \
	VMOVDQU (16*2)(DX), B2; \
	VPXOR (16*2)(SP), B2, B2; \
	VMOVDQU (16*3)(DX), B3; \
	VPXOR (16*3)(SP), B3, B3

#define avxStore4Blocks \
	VPXOR (16*0)(SP), B0, B0; \
	VMOVDQU B0, (16*0)(CX); \
	VPXOR (16*1)(SP), B1, B1; \
	VMOVDQU B1, (16*1)(CX); \
	VPXOR (16*2)(SP), B2, B2; \
	VMOVDQU B2, (16*2)(CX); \
	VPXOR (16*3)(SP), B3, B3; \
	VMOVDQU B3, (16*3)(CX)

#define avxLoad8Blocks \
	avxLoad4Blocks; \
	VMOVDQU (16*4)(DX), B4; \
	VPXOR (16*4)(SP), B4, B4; \
	VMOVDQU (16*5)(DX), B5; \
	VPXOR (16*5)(SP), B5, B5; \
	VMOVDQU (16*6)(DX), B6; \
	VPXOR (16*6)(SP), B6, B6; \
	VMOVDQU (16*7)(DX), B7; \
	VPXOR (16*7)(SP), B7, B7

#define avxStore8Blocks \
	avxStore4Blocks; \
	VPXOR (16*4)(SP), B4, B4; \
	VMOVDQU B4, (16*4)(CX); \
	VPXOR (16*5)(SP), B5, B5; \
	VMOVDQU B5, (16*5)(CX); \
	VPXOR (16*6)(SP), B6, B6; \
	VMOVDQU B6, (16*6)(CX); \
	VPXOR (16*7)(SP), B7, B7; \
	VMOVDQU B7, (16*7)(CX)
