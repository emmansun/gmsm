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

DATA p256p<>+0x00(SB)/8, $0xffffffffffffffff
DATA p256p<>+0x08(SB)/8, $0xffffffff00000000
DATA p256p<>+0x10(SB)/8, $0xffffffffffffffff
DATA p256p<>+0x18(SB)/8, $0xfffffffeffffffff
DATA p256ordK0<>+0x00(SB)/8, $0x327f9e8872350975
DATA p256ord<>+0x00(SB)/8, $0x53bbf40939d54123
DATA p256ord<>+0x08(SB)/8, $0x7203df6b21c6052b
DATA p256ord<>+0x10(SB)/8, $0xffffffffffffffff
DATA p256ord<>+0x18(SB)/8, $0xfffffffeffffffff
DATA p256one<>+0x00(SB)/8, $0x0000000000000001
DATA p256one<>+0x08(SB)/8, $0x00000000ffffffff
DATA p256one<>+0x10(SB)/8, $0x0000000000000000
DATA p256one<>+0x18(SB)/8, $0x0000000100000000
GLOBL p256p<>(SB), 8, $32
GLOBL p256ordK0<>(SB), 8, $8
GLOBL p256ord<>(SB), 8, $32
GLOBL p256one<>(SB), 8, $32

#define p256SqrMontReduce() \
	\ // First reduction step, [p3, p2, p1, p0] = [1, -0x100000000, 0, (1 - 0x100000000), -1]
	MOVQ acc0, AX            \
	MOVQ acc0, DX            \
	SHLQ $32, AX             \  // AX = L(acc0 * 2^32), low part
	SHRQ $32, DX             \  // DX = H(acc0 * 2^32), high part
	\// calculate the negative part: [0, -0x100000000, 0, -0x100000000] * acc0
	SUBQ AX, acc1            \ 
	SBBQ DX, acc2            \
	SBBQ AX, acc3            \
	MOVQ acc0, AX            \
	SBBQ DX, acc0            \
	\ // calculate the positive part: [1, 0, 0, 1] * acc0 + [0, acc3, acc2, acc1], 
	\ // due to (-1) * acc0 + acc0 == 0, so last lowest lamb 0 is dropped directly, no carry.
	ADDQ AX, acc1            \ // acc1' = L (acc0 + acc1)
	ADCQ $0, acc2            \ // acc2' = acc2 + carry1
	ADCQ $0, acc3            \ // acc3' = acc3 + carry2
	ADCQ $0, acc0            \ // acc0' = acc0 + carry3
	\ // Second reduction step
	MOVQ acc1, AX            \
	MOVQ acc1, DX            \
	SHLQ $32, AX             \
	SHRQ $32, DX             \
	\
	SUBQ AX, acc2            \
	SBBQ DX, acc3            \
	SBBQ AX, acc0            \
	MOVQ acc1, AX            \
	SBBQ DX, acc1            \
	\
	ADDQ AX, acc2            \
	ADCQ $0, acc3            \
	ADCQ $0, acc0            \
	ADCQ $0, acc1            \
	\ // Third reduction step
	MOVQ acc2, AX            \
	MOVQ acc2, DX            \
	SHLQ $32, AX             \
	SHRQ $32, DX             \
	\
	SUBQ AX, acc3            \
	SBBQ DX, acc0            \
	SBBQ AX, acc1            \
	MOVQ acc2, AX            \
	SBBQ DX, acc2            \
	\
	ADDQ AX, acc3            \
	ADCQ $0, acc0            \
	ADCQ $0, acc1            \
	ADCQ $0, acc2            \
	\ // Last reduction step
	XORQ t0, t0              \
	MOVQ acc3, AX            \
	MOVQ acc3, DX            \
	SHLQ $32, AX             \
	SHRQ $32, DX             \
	\
	SUBQ AX, acc0            \
	SBBQ DX, acc1            \
	SBBQ AX, acc2            \
	MOVQ acc3, AX            \
	SBBQ DX, acc3            \
	\
	ADDQ AX, acc0            \
	ADCQ $0, acc1            \
	ADCQ $0, acc2            \
	ADCQ $0, acc3            \
	\ // Add bits [511:256] of the sqr result
	ADCQ acc4, acc0          \
	ADCQ acc5, acc1          \
	ADCQ y_ptr, acc2         \
	ADCQ x_ptr, acc3         \
	ADCQ $0, t0

#define p256PrimReduce(a0, a1, a2, a3, a4, b0, b1, b2, b3, res) \
	MOVQ a0, b0            \
	MOVQ a1, b1            \
	MOVQ a2, b2            \
	MOVQ a3, b3                        \
	\ // Subtract p256
	SUBQ $-1, a0                       \
	SBBQ p256p<>+0x08(SB), a1          \
	SBBQ $-1, a2                       \
	SBBQ p256p<>+0x018(SB), a3         \
	SBBQ $0, a4                          \
	\
	CMOVQCS b0, a0                   \
	CMOVQCS b1, a1                   \
	CMOVQCS b2, a2                  \
	CMOVQCS b3, a3                     \
	\
	MOVQ a0, (8*0)(res)            \
	MOVQ a1, (8*1)(res)            \
	MOVQ a2, (8*2)(res)            \
	MOVQ a3, (8*3)(res)

/* ---------------------------------------*/
#define p256OrdReduceInline(a0, a1, a2, a3, a4, b0, b1, b2, b3, res) \
	\// Copy result [255:0]
	MOVQ a0, b0                    \
	MOVQ a1, b1                    \
	MOVQ a2, b2                    \
	MOVQ a3, b3                    \
	\// Subtract p256
	SUBQ p256ord<>+0x00(SB), a0    \
	SBBQ p256ord<>+0x08(SB) ,a1    \
	SBBQ p256ord<>+0x10(SB), a2    \
	SBBQ p256ord<>+0x18(SB), a3    \
	SBBQ $0, a4                    \
	\
	CMOVQCS b0, a0                 \
	CMOVQCS b1, a1                 \
	CMOVQCS b2, a2                 \
	CMOVQCS b3, a3                 \
	\
	MOVQ a0, (8*0)(res)            \
	MOVQ a1, (8*1)(res)            \
	MOVQ a2, (8*2)(res)            \
	MOVQ a3, (8*3)(res)

#define sm2P256SqrReductionInternal() \
	\ // First reduction step
	MOVQ acc0, mul0                   \
	MOVQ acc0, mul1                   \
	SHLQ $32, mul0                    \
	SHRQ $32, mul1                    \
	\
	SUBQ mul0, acc1                   \
	SBBQ mul1, acc2                   \
	SBBQ mul0, acc3                   \
	MOVQ acc0, mul0                   \
	SBBQ mul1, acc0                   \
	\
	ADDQ mul0, acc1                   \
	ADCQ $0, acc2                     \
	ADCQ $0, acc3                     \
	ADCQ $0, acc0                     \
	\ // Second reduction step
	MOVQ acc1, mul0                   \
	MOVQ acc1, mul1                   \
	SHLQ $32, mul0                    \
	SHRQ $32, mul1                    \
	\
	SUBQ mul0, acc2                   \
	SBBQ mul1, acc3                   \
	SBBQ mul0, acc0                   \
	MOVQ acc1, mul0                   \
	SBBQ mul1, acc1                   \
	\
	ADDQ mul0, acc2                   \
	ADCQ $0, acc3                     \
	ADCQ $0, acc0                     \
	ADCQ $0, acc1                     \
	\ // Third reduction step
	MOVQ acc2, mul0                   \
	MOVQ acc2, mul1                   \
	SHLQ $32, mul0                    \
	SHRQ $32, mul1                    \
	\
	SUBQ mul0, acc3                   \
	SBBQ mul1, acc0                   \
	SBBQ mul0, acc1                   \
	MOVQ acc2, mul0                   \
	SBBQ mul1, acc2                   \
	\
	ADDQ mul0, acc3                   \
	ADCQ $0, acc0                     \
	ADCQ $0, acc1                     \
	ADCQ $0, acc2                     \
	\ // Last reduction step
	MOVQ acc3, mul0                   \
	MOVQ acc3, mul1                   \
	SHLQ $32, mul0                    \
	SHRQ $32, mul1                    \
	\
	SUBQ mul0, acc0                   \
	SBBQ mul1, acc1                   \
	SBBQ mul0, acc2                   \
	MOVQ acc3, mul0                   \
	SBBQ mul1, acc3                   \
	\
	ADDQ mul0, acc0                   \
	ADCQ $0, acc1                     \
	ADCQ $0, acc2                     \
	ADCQ $0, acc3                     \
	MOVQ $0, mul0                       \
	\ // Add bits [511:256] of the result
	ADCQ acc0, t0                     \
	ADCQ acc1, t1                     \
	ADCQ acc2, t2                     \
	ADCQ acc3, t3                     \
	ADCQ $0, mul0                      \
	\ // Copy result
	MOVQ t0, acc4                     \
	MOVQ t1, acc5                     \
	MOVQ t2, acc6                     \
	MOVQ t3, acc7                     \
	\ // Subtract p256
	SUBQ $-1, acc4                     \
	SBBQ p256p<>+0x08(SB), acc5        \
	SBBQ $-1, acc6                     \
	SBBQ p256p<>+0x018(SB), acc7       \
	SBBQ $0, mul0                       \
	\ // If the result of the subtraction is negative, restore the previous result
	CMOVQCS t0, acc4                   \
	CMOVQCS t1, acc5                   \
	CMOVQCS t2, acc6                   \
	CMOVQCS t3, acc7

#define p256PointDoubleInit() \
	MOVOU (16*0)(BX), X0 \
	MOVOU (16*1)(BX), X1 \
	MOVOU (16*2)(BX), X2 \
	MOVOU (16*3)(BX), X3 \
	MOVOU (16*4)(BX), X4 \
	MOVOU (16*5)(BX), X5 \
	\
	MOVOU X0, x(16*0) \
	MOVOU X1, x(16*1) \
	MOVOU X2, y(16*0) \
	MOVOU X3, y(16*1) \
	MOVOU X4, z(16*0) \
	MOVOU X5, z(16*1)

/* ---------------------------------------*/
// [t3, t2, t1, t0] = 2[acc7, acc6, acc5, acc4]
#define p256MulBy2Inline\
	XORQ mul0, mul0;\
	ADDQ acc4, acc4;\
	ADCQ acc5, acc5;\
	ADCQ acc6, acc6;\
	ADCQ acc7, acc7;\
	ADCQ $0, mul0;\
	MOVQ acc4, t0;\
	MOVQ acc5, t1;\
	MOVQ acc6, t2;\
	MOVQ acc7, t3;\
	SUBQ $-1, t0;\
	SBBQ p256p<>+0x08(SB), t1;\
	SBBQ $-1, t2;\
	SBBQ p256p<>+0x018(SB), t3;\
	SBBQ $0, mul0;\
	CMOVQCS acc4, t0;\
	CMOVQCS acc5, t1;\
	CMOVQCS acc6, t2;\
	CMOVQCS acc7, t3;
/* ---------------------------------------*/
// [t3, t2, t1, t0] = [acc7, acc6, acc5, acc4] + [t3, t2, t1, t0]
#define p256AddInline \
	XORQ mul0, mul0;\
	ADDQ t0, acc4;\
	ADCQ t1, acc5;\
	ADCQ t2, acc6;\
	ADCQ t3, acc7;\
	ADCQ $0, mul0;\
	MOVQ acc4, t0;\
	MOVQ acc5, t1;\
	MOVQ acc6, t2;\
	MOVQ acc7, t3;\
	SUBQ $-1, t0;\
	SBBQ p256p<>+0x08(SB), t1;\
	SBBQ $-1, t2;\
	SBBQ p256p<>+0x018(SB), t3;\
	SBBQ $0, mul0;\
	CMOVQCS acc4, t0;\
	CMOVQCS acc5, t1;\
	CMOVQCS acc6, t2;\
	CMOVQCS acc7, t3;
