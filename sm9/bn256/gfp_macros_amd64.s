#define res_ptr DI
#define x_ptr SI
#define y_ptr CX

#define acc0 R8
#define acc1 R9
#define acc2 R10
#define acc3 R11
#define acc4 R12
#define acc5 R13
#define t0 R14

#define storeBlock(a0,a1,a2,a3, r) \
	MOVQ a0,  0+r \
	MOVQ a1,  8+r \
	MOVQ a2, 16+r \
	MOVQ a3, 24+r

#define loadBlock(r, a0,a1,a2,a3) \
	MOVQ  0+r, a0 \
	MOVQ  8+r, a1 \
	MOVQ 16+r, a2 \
	MOVQ 24+r, a3

#define gfpCarry(a0,a1,a2,a3, b0,b1,b2,b3,b4) \
	\ // b = a-p
	MOVQ a0, b0 \
	MOVQ a1, b1 \
	MOVQ a2, b2 \
	MOVQ a3, b3 \
	\
	SUBQ ·p2+0(SB), b0 \
	SBBQ ·p2+8(SB), b1 \
	SBBQ ·p2+16(SB), b2 \
	SBBQ ·p2+24(SB), b3 \
	SBBQ $0, b4 \
	\
	\ // if b is negative then return a
	\ // else return b
	CMOVQCC b0, a0 \
	CMOVQCC b1, a1 \
	CMOVQCC b2, a2 \
	CMOVQCC b3, a3

#define gfpCarryWithoutCarry(a0,a1,a2,a3, b0,b1,b2,b3) \
	\ // b = a-p
	MOVQ a0, b0 \
	MOVQ a1, b1 \
	MOVQ a2, b2 \
	MOVQ a3, b3 \
	\
	SUBQ ·p2+0(SB), b0 \
	SBBQ ·p2+8(SB), b1 \
	SBBQ ·p2+16(SB), b2 \
	SBBQ ·p2+24(SB), b3 \
	\
	\ // if b is negative then return a
	\ // else return b
	CMOVQCC b0, a0 \
	CMOVQCC b1, a1 \
	CMOVQCC b2, a2 \
	CMOVQCC b3, a3
