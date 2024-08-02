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

#define p256SqrMontReduceInline \
	\ // First reduction step, [p3, p2, p1, p0] = [1, -0x100000000, 0, (1 - 0x100000000), -1]
	MOVQ acc0, AX     \
	MOVQ acc0, DX     \
	SHLQ $32, AX      \
	SHRQ $32, DX      \
	\// calculate the negative part: [1, -0x100000000, 0, -0x100000000] * acc0 + [0, acc3, acc2, acc1]
	SUBQ AX, acc1     \ 
	SBBQ DX, acc2     \
	SBBQ AX, acc3     \
	MOVQ acc0, AX     \
	SBBQ DX, acc0     \
	\ // calculate the positive part: [0, 0, 0, AX] + [acc0, acc3, acc2, acc1], 
	\ // due to (-1) * acc0 + acc0 == 0, so last lowest lamb 0 is dropped directly, no carry.
	ADDQ AX, acc1     \
	ADCQ $0, acc2     \
	ADCQ $0, acc3     \
	ADCQ $0, acc0     \
	\ // Second reduction step
	MOVQ acc1, AX     \
	MOVQ acc1, DX     \
	SHLQ $32, AX      \
	SHRQ $32, DX      \
	\
	SUBQ AX, acc2     \
	SBBQ DX, acc3     \
	SBBQ AX, acc0     \
	MOVQ acc1, AX     \
	SBBQ DX, acc1     \
	\
	ADDQ AX, acc2     \
	ADCQ $0, acc3     \
	ADCQ $0, acc0     \
	ADCQ $0, acc1     \
	\ // Third reduction step
	MOVQ acc2, AX     \
	MOVQ acc2, DX     \
	SHLQ $32, AX      \
	SHRQ $32, DX      \
	\
	SUBQ AX, acc3     \
	SBBQ DX, acc0     \
	SBBQ AX, acc1     \
	MOVQ acc2, AX     \
	SBBQ DX, acc2     \
	\
	ADDQ AX, acc3     \
	ADCQ $0, acc0     \
	ADCQ $0, acc1     \
	ADCQ $0, acc2     \
	\ // Last reduction step
	XORQ t0, t0       \
	MOVQ acc3, AX     \
	MOVQ acc3, DX     \
	SHLQ $32, AX      \
	SHRQ $32, DX      \
	\
	SUBQ AX, acc0     \
	SBBQ DX, acc1     \
	SBBQ AX, acc2     \
	MOVQ acc3, AX     \
	SBBQ DX, acc3     \
	\
	ADDQ AX, acc0     \
	ADCQ $0, acc1     \
	ADCQ $0, acc2     \
	ADCQ $0, acc3     \
	\ // Add bits [511:256] of the sqr result
	ADCQ acc4, acc0   \
	ADCQ acc5, acc1   \
	ADCQ y_ptr, acc2  \
	ADCQ x_ptr, acc3  \
	ADCQ $0, t0

/* ---------------------------------------*/
#define p256PrimReduce(a0, a1, a2, a3, a4, b0, b1, b2, b3, res) \
	MOVQ a0, b0                 \
	MOVQ a1, b1                 \
	MOVQ a2, b2                 \
	MOVQ a3, b3                 \
	\ // Subtract p256
	SUBQ $-1, a0                \
	SBBQ p256p<>+0x08(SB), a1   \
	SBBQ $-1, a2                \
	SBBQ p256p<>+0x018(SB), a3  \
	SBBQ $0, a4                 \
	\ // If the result of the subtraction is negative, restore the previous result
	CMOVQCS b0, a0              \ // CMOVQCS: Move if below (CF == 1)
	CMOVQCS b1, a1              \
	CMOVQCS b2, a2              \
	CMOVQCS b3, a3              \
	\
	MOVQ a0, (8*0)(res)         \
	MOVQ a1, (8*1)(res)         \
	MOVQ a2, (8*2)(res)         \
	MOVQ a3, (8*3)(res)

/* ---------------------------------------*/
#define p256OrdReduceInline(a0, a1, a2, a3, a4, b0, b1, b2, b3, res) \
	\// Copy result [255:0]
	MOVQ a0, b0                    \
	MOVQ a1, b1                    \
	MOVQ a2, b2                    \
	MOVQ a3, b3                    \
	\// Subtract p256ord
	SUBQ p256ord<>+0x00(SB), a0    \
	SBBQ p256ord<>+0x08(SB) ,a1    \
	SBBQ p256ord<>+0x10(SB), a2    \
	SBBQ p256ord<>+0x18(SB), a3    \
	SBBQ $0, a4                    \
	\ // If the result of the subtraction is negative, restore the previous result
	CMOVQCS b0, a0                 \ // CMOVQCS: Move if below (CF == 1)
	CMOVQCS b1, a1                 \
	CMOVQCS b2, a2                 \
	CMOVQCS b3, a3                 \
	\
	MOVQ a0, (8*0)(res)            \
	MOVQ a1, (8*1)(res)            \
	MOVQ a2, (8*2)(res)            \
	MOVQ a3, (8*3)(res)

/* ---------------------------------------*/
#define sm2P256SqrReductionInline \
	\ // First reduction step
	MOVQ acc0, mul0             \
	MOVQ acc0, mul1             \
	SHLQ $32, mul0              \
	SHRQ $32, mul1              \
	\
	SUBQ mul0, acc1             \
	SBBQ mul1, acc2             \
	SBBQ mul0, acc3             \
	MOVQ acc0, mul0             \
	SBBQ mul1, acc0             \
	\
	ADDQ mul0, acc1             \
	ADCQ $0, acc2               \
	ADCQ $0, acc3               \
	ADCQ $0, acc0               \
	\ // Second reduction step
	MOVQ acc1, mul0             \
	MOVQ acc1, mul1             \
	SHLQ $32, mul0              \
	SHRQ $32, mul1              \
	\
	SUBQ mul0, acc2             \
	SBBQ mul1, acc3             \
	SBBQ mul0, acc0             \
	MOVQ acc1, mul0             \
	SBBQ mul1, acc1             \
	\
	ADDQ mul0, acc2             \
	ADCQ $0, acc3               \
	ADCQ $0, acc0               \
	ADCQ $0, acc1               \
	\ // Third reduction step
	MOVQ acc2, mul0             \
	MOVQ acc2, mul1             \
	SHLQ $32, mul0              \
	SHRQ $32, mul1              \
	\
	SUBQ mul0, acc3             \
	SBBQ mul1, acc0             \
	SBBQ mul0, acc1             \
	MOVQ acc2, mul0             \
	SBBQ mul1, acc2             \
	\
	ADDQ mul0, acc3             \
	ADCQ $0, acc0               \
	ADCQ $0, acc1               \
	ADCQ $0, acc2               \
	\ // Last reduction step
	MOVQ acc3, mul0             \
	MOVQ acc3, mul1             \
	SHLQ $32, mul0              \
	SHRQ $32, mul1              \
	\
	SUBQ mul0, acc0             \
	SBBQ mul1, acc1             \
	SBBQ mul0, acc2             \
	MOVQ acc3, mul0             \
	SBBQ mul1, acc3             \
	\
	ADDQ mul0, acc0             \
	ADCQ $0, acc1               \
	ADCQ $0, acc2               \
	ADCQ $0, acc3               \
	MOVQ $0, mul0               \
	\ // Add bits [511:256] of the result
	ADCQ acc0, t0               \
	ADCQ acc1, t1               \
	ADCQ acc2, t2               \
	ADCQ acc3, t3               \
	ADCQ $0, mul0               \
	\ // Copy result
	MOVQ t0, acc4               \
	MOVQ t1, acc5               \
	MOVQ t2, acc6               \
	MOVQ t3, acc7               \
	\ // Subtract p256
	SUBQ $-1, acc4              \
	SBBQ p256p<>+0x08(SB), acc5 \
	SBBQ $-1, acc6              \
	SBBQ p256p<>+0x018(SB), acc7\
	SBBQ $0, mul0               \
	\ // If the result of the subtraction is negative, restore the previous result
	CMOVQCS t0, acc4            \ // CMOVQCS: Move if below (CF == 1)
	CMOVQCS t1, acc5            \
	CMOVQCS t2, acc6            \
	CMOVQCS t3, acc7

/* ---------------------------------------*/
#define sm2P256MulReductionInline \
	\// First reduction step
	MOVQ acc0, mul0              \
	MOVQ acc0, mul1              \
	SHLQ $32, mul0               \
	SHRQ $32, mul1               \
	\
	SUBQ mul0, acc1              \
	SBBQ mul1, acc2              \
	SBBQ mul0, acc3              \
	MOVQ acc0, mul0              \
	SBBQ mul1, acc0              \
	\
	ADDQ mul0, acc1              \
	ADCQ $0, acc2                \
	ADCQ $0, acc3                \
	ADCQ $0, acc0                \
	\// Second reduction step
	MOVQ acc1, mul0              \
	MOVQ acc1, mul1              \
	SHLQ $32, mul0               \
	SHRQ $32, mul1               \
	\
	SUBQ mul0, acc2              \
	SBBQ mul1, acc3              \
	SBBQ mul0, acc0              \
	MOVQ acc1, mul0              \
	SBBQ mul1, acc1              \
	\
	ADDQ mul0, acc2              \
	ADCQ $0, acc3                \
	ADCQ $0, acc0                \
	ADCQ $0, acc1                \
	\// Third reduction step
	MOVQ acc2, mul0              \
	MOVQ acc2, mul1              \
	SHLQ $32, mul0               \
	SHRQ $32, mul1               \
	\
	SUBQ mul0, acc3              \
	SBBQ mul1, acc0              \
	SBBQ mul0, acc1              \
	MOVQ acc2, mul0              \
	SBBQ mul1, acc2              \
	\
	ADDQ mul0, acc3              \
	ADCQ $0, acc0                \
	ADCQ $0, acc1                \
	ADCQ $0, acc2                \
	\// Last reduction step
	MOVQ acc3, mul0              \
	MOVQ acc3, mul1              \
	SHLQ $32, mul0               \
	SHRQ $32, mul1               \
	\
	SUBQ mul0, acc0              \
	SBBQ mul1, acc1              \
	SBBQ mul0, acc2              \
	MOVQ acc3, mul0              \
	SBBQ mul1, acc3              \
	\
	ADDQ mul0, acc0              \
	ADCQ $0, acc1                \
	ADCQ $0, acc2                \
	ADCQ $0, acc3

/* ---------------------------------------*/
#define p256SqrRound(t1) \
	\// y[1:] * y[0]
	MOVQ (8*0)(x_ptr), t0;\
	\
	MOVQ (8*1)(x_ptr), AX;\
	MULQ t0;\
	MOVQ AX, acc1;\
	MOVQ DX, acc2;\
	\
	MOVQ (8*2)(x_ptr), AX;\
	MULQ t0;\
	ADDQ AX, acc2;\
	ADCQ $0, DX;\
	MOVQ DX, acc3;\
	\
	MOVQ (8*3)(x_ptr), AX;\
	MULQ t0;\
	ADDQ AX, acc3;\
	ADCQ $0, DX;\
	MOVQ DX, acc4;\
	\// y[2:] * y[1]
	MOVQ (8*1)(x_ptr), t0;\
	\
	MOVQ (8*2)(x_ptr), AX;\
	MULQ t0;\
	ADDQ AX, acc3;\
	ADCQ $0, DX;\
	MOVQ DX, t1;\
	\
	MOVQ (8*3)(x_ptr), AX;\
	MULQ t0;\
	ADDQ t1, acc4;\
	ADCQ $0, DX;\
	ADDQ AX, acc4;\
	ADCQ $0, DX;\
	MOVQ DX, acc5;\
	\// y[3] * y[2]
	MOVQ (8*2)(x_ptr), t0;\
	\
	MOVQ (8*3)(x_ptr), AX;\
	MULQ t0;\
	ADDQ AX, acc5;\
	ADCQ $0, DX;\
	MOVQ DX, y_ptr;\
	XORQ t1, t1;\
	\// *2
	ADDQ acc1, acc1;\
	ADCQ acc2, acc2;\
	ADCQ acc3, acc3;\
	ADCQ acc4, acc4;\
	ADCQ acc5, acc5;\
	ADCQ y_ptr, y_ptr;\
	ADCQ $0, t1;\
	\// Missing products
	MOVQ (8*0)(x_ptr), AX;\
	MULQ AX;\
	MOVQ AX, acc0;\
	MOVQ DX, t0;\
	\
	MOVQ (8*1)(x_ptr), AX;\
	MULQ AX;\
	ADDQ t0, acc1;\
	ADCQ AX, acc2;\
	ADCQ $0, DX;\
	MOVQ DX, t0;\
	\
	MOVQ (8*2)(x_ptr), AX;\
	MULQ AX;\
	ADDQ t0, acc3;\
	ADCQ AX, acc4;\
	ADCQ $0, DX;\
	MOVQ DX, t0;\
	\
	MOVQ (8*3)(x_ptr), AX;\
	MULQ AX;\
	ADDQ t0, acc5;\
	ADCQ AX, y_ptr;\
	ADCQ DX, t1;\
	MOVQ t1, x_ptr;\
	\// T = [x_ptr, y_ptr, acc5, acc4, acc3, acc2, acc1, acc0]
	p256SqrMontReduceInline;\
	p256PrimReduce(acc0, acc1, acc2, acc3, t0, acc4, acc5, y_ptr, t1, res_ptr);\
	MOVQ res_ptr, x_ptr;

/* ---------------------------------------*/
#define p256SqrRoundAdx(t1) \
	XORQ acc0, acc0;\
	XORQ y_ptr, y_ptr;\
	\// x[1:] * x[0]
	MOVQ (8*0)(x_ptr), DX;\
	MULXQ (8*1)(x_ptr), acc1, acc2;\
	\
	MULXQ (8*2)(x_ptr), AX, acc3;\
	ADOXQ AX, acc2;\
	\
	MULXQ (8*3)(x_ptr), AX, acc4;\
	ADOXQ AX, acc3;\
	ADOXQ y_ptr, acc4;\
	\
	\// x[2:] * x[1]
	MOVQ (8*1)(x_ptr), DX;\
	MULXQ (8*2)(x_ptr), AX, t1;\
	ADOXQ AX, acc3;\
	\
	MULXQ (8*3)(x_ptr), AX, acc5;\
	ADCXQ t1, AX;\
	ADOXQ AX, acc4;\
	ADCXQ y_ptr, acc5;\
	\
	\// y[x] * x[2]
	MOVQ (8*2)(x_ptr), DX;\
	MULXQ (8*3)(x_ptr), AX, y_ptr ;\
	ADOXQ AX, acc5;\
	ADOXQ acc0, y_ptr;\
	\
	XORQ t1, t1;\
	\
	\// *2
	ADOXQ acc1, acc1;\
	ADOXQ acc2, acc2;\
	ADOXQ acc3, acc3;\
	ADOXQ acc4, acc4;\
	ADOXQ acc5, acc5;\
	ADOXQ y_ptr, y_ptr;\
	ADOXQ acc0, t1;\
	\
	\// Missing products
	MOVQ (8*0)(x_ptr), DX;\
	MULXQ DX, acc0, t0;\
	ADCXQ t0, acc1;\
	\
	MOVQ (8*1)(x_ptr), DX;\
	MULXQ DX, AX, t0;\
	ADCXQ AX, acc2;\
	ADCXQ t0, acc3;\
	\
	MOVQ (8*2)(x_ptr), DX;\
	MULXQ DX, AX, t0 ;\
	ADCXQ AX, acc4;\
	ADCXQ t0, acc5;\
	\
	MOVQ (8*3)(x_ptr), DX;\
	MULXQ DX, AX, x_ptr;\
	ADCXQ AX, y_ptr;\
	ADCXQ t1, x_ptr;\
	\
	\// T = [x_ptr, y_ptr, acc5, acc4, acc3, acc2, acc1, acc0]
	p256SqrMontReduceInline;\
	p256PrimReduce(acc0, acc1, acc2, acc3, t0, acc4, acc5, y_ptr, t1, res_ptr);\
	MOVQ res_ptr, x_ptr;

/* ---------------------------------------*/
#define p256OrdSqrRound(t1) \
	\// y[1:] * y[0]
	MOVQ (8*0)(x_ptr), t0;\
	\
	MOVQ (8*1)(x_ptr), AX;\
	MULQ t0;\
	MOVQ AX, acc1;\
	MOVQ DX, acc2;\
	\
	MOVQ (8*2)(x_ptr), AX;\
	MULQ t0;\
	ADDQ AX, acc2;\
	ADCQ $0, DX;\
	MOVQ DX, acc3;\
	\
	MOVQ (8*3)(x_ptr), AX;\
	MULQ t0;\
	ADDQ AX, acc3;\
	ADCQ $0, DX;\
	MOVQ DX, acc4;\
	\// y[2:] * y[1]
	MOVQ (8*1)(x_ptr), t0;\
	\
	MOVQ (8*2)(x_ptr), AX;\
	MULQ t0;\
	ADDQ AX, acc3;\
	ADCQ $0, DX;\
	MOVQ DX, t1;\
	\
	MOVQ (8*3)(x_ptr), AX;\
	MULQ t0;\
	ADDQ t1, acc4;\
	ADCQ $0, DX;\
	ADDQ AX, acc4;\
	ADCQ $0, DX;\
	MOVQ DX, acc5;\
	\// y[3] * y[2]
	MOVQ (8*2)(x_ptr), t0;\
	\
	MOVQ (8*3)(x_ptr), AX;\
	MULQ t0;\
	ADDQ AX, acc5;\
	ADCQ $0, DX;\
	MOVQ DX, y_ptr;\
	XORQ t1, t1;\
	\// *2
	ADDQ acc1, acc1;\
	ADCQ acc2, acc2;\
	ADCQ acc3, acc3;\
	ADCQ acc4, acc4;\
	ADCQ acc5, acc5;\
	ADCQ y_ptr, y_ptr;\
	ADCQ $0, t1;\
	\// Missing products
	MOVQ (8*0)(x_ptr), AX;\
	MULQ AX;\
	MOVQ AX, acc0;\
	MOVQ DX, t0;\
	\
	MOVQ (8*1)(x_ptr), AX;\
	MULQ AX;\
	ADDQ t0, acc1;\
	ADCQ AX, acc2;\
	ADCQ $0, DX;\
	MOVQ DX, t0;\
	\
	MOVQ (8*2)(x_ptr), AX;\
	MULQ AX;\
	ADDQ t0, acc3;\
	ADCQ AX, acc4;\
	ADCQ $0, DX;\
	MOVQ DX, t0;\
	\
	MOVQ (8*3)(x_ptr), AX;\
	MULQ AX;\
	ADDQ t0, acc5;\
	ADCQ AX, y_ptr;\
	ADCQ DX, t1;\
	MOVQ t1, x_ptr;\
	\
	\// T = [x_ptr, y_ptr, acc5, acc4, acc3, acc2, acc1, acc0]
	MOVQ acc0, AX;\
	MULQ p256ordK0<>(SB);\
	MOVQ AX, t0;\ // Y = t0 = (k0 * acc0) mod 2^64
	\
	MOVQ p256ord<>+0x00(SB), AX;\
	MULQ t0;\
	ADDQ AX, acc0;\ // (carry1, acc0) = acc0 + L(t0 * ord0)
	ADCQ $0, DX;\ // DX = carry1 + H(t0 * ord0)
	MOVQ DX, t1;\ // t1 = carry1 + H(t0 * ord0)
	MOVQ t0, acc0;\ // acc0 =  t0
	\
	\// calculate the negative part: [acc0, acc3, acc2, acc1] - [0, 0x100000000, 1, 0] * t0
	MOVQ t0, AX;\
	MOVQ t0, DX;\
	SHLQ $32, AX;\
	SHRQ $32, DX;\
	\
	SUBQ t0, acc2;\
	SBBQ AX, acc3;\
	SBBQ DX, acc0;\
	\
	MOVQ p256ord<>+0x08(SB), AX;\
	MULQ t0;\
	ADDQ t1, acc1;\ // (carry2, acc1) = acc1 + t1
	ADCQ $0, DX;\ // DX = carry2 + H(t0*ord1)
	\
	ADDQ AX, acc1;\ // (carry3, acc1) = acc1 + t1 + L(t0*ord1)
	ADCQ DX, acc2;\
	ADCQ $0, acc3;\
	ADCQ $0, acc0;\
	\
	\// Second reduction step
	MOVQ acc1, AX;\
	MULQ p256ordK0<>(SB);\
	MOVQ AX, t0;\
	\
	MOVQ p256ord<>+0x00(SB), AX;\
	MULQ t0;\
	ADDQ AX, acc1;\
	ADCQ $0, DX;\
	MOVQ DX, t1;\
	MOVQ t0, acc1;\
	\
	MOVQ t0, AX;\
	MOVQ t0, DX;\
	SHLQ $32, AX;\
	SHRQ $32, DX;\
	\
	SUBQ t0, acc3;\
	SBBQ AX, acc0;\
	SBBQ DX, acc1;\
	\
	MOVQ p256ord<>+0x08(SB), AX;\
	MULQ t0;\
	ADDQ t1, acc2;\
	ADCQ $0, DX;\
	\
	ADDQ AX, acc2;\
	ADCQ DX, acc3;\
	ADCQ $0, acc0;\
	ADCQ $0, acc1;\
	\
	\// Third reduction step
	MOVQ acc2, AX;\
	MULQ p256ordK0<>(SB);\
	MOVQ AX, t0;\
	\
	MOVQ p256ord<>+0x00(SB), AX;\
	MULQ t0;\
	ADDQ AX, acc2;\
	ADCQ $0, DX;\
	MOVQ DX, t1;\
	MOVQ t0, acc2;\
	\
	MOVQ t0, AX;\
	MOVQ t0, DX;\
	SHLQ $32, AX;\
	SHRQ $32, DX;\
	\
	SUBQ t0, acc0;\
	SBBQ AX, acc1;\
	SBBQ DX, acc2;\
	\
	MOVQ p256ord<>+0x08(SB), AX;\
	MULQ t0;\
	ADDQ t1, acc3;\
	ADCQ $0, DX;\
	\
	ADDQ AX, acc3;\
	ADCQ DX, acc0;\
	ADCQ $0, acc1;\
	ADCQ $0, acc2;\
	\
	\// Last reduction step
	MOVQ acc3, AX;\
	MULQ p256ordK0<>(SB);\
	MOVQ AX, t0;\
	\
	MOVQ p256ord<>+0x00(SB), AX;\
	MULQ t0;\
	ADDQ AX, acc3;\
	ADCQ $0, DX;\
	MOVQ DX, t1;\
	MOVQ t0, acc3;\
	\
	MOVQ t0, AX;\
	MOVQ t0, DX;\
	SHLQ $32, AX;\
	SHRQ $32, DX;\
	\
	SUBQ t0, acc1;\
	SBBQ AX, acc2;\
	SBBQ DX, acc3;\
	\
	MOVQ p256ord<>+0x08(SB), AX;\
	MULQ t0;\
	ADDQ t1, acc0;\
	ADCQ $0, DX;\
	\
	ADDQ AX, acc0;\
	ADCQ DX, acc1;\
	ADCQ $0, acc2;\
	ADCQ $0, acc3;\
	XORQ t0, t0;\
	\// Add bits [511:256] of the sqr result
	ADCQ acc4, acc0;\
	ADCQ acc5, acc1;\
	ADCQ y_ptr, acc2;\
	ADCQ x_ptr, acc3;\
	ADCQ $0, t0;\
	\
	p256OrdReduceInline(acc0, acc1, acc2, acc3, t0, acc4, acc5, y_ptr, t1, res_ptr);\
	MOVQ res_ptr, x_ptr;

/* ---------------------------------------*/
#define p256OrdSqrRoundAdx(t1) \
	XORQ acc0, acc0;\
	XORQ y_ptr, y_ptr;\
	\// y[1:] * y[0]
	MOVQ (8*0)(x_ptr), DX;\
	MULXQ (8*1)(x_ptr), acc1, acc2 ;\
	\
	MULXQ (8*2)(x_ptr), AX, acc3;\
	ADOXQ AX, acc2;\
	\
	MULXQ (8*3)(x_ptr), AX, acc4;\
	ADOXQ AX, acc3;\
	ADOXQ y_ptr, acc4;\
	\
	\// y[2:] * y[1]
	MOVQ (8*1)(x_ptr), DX;\
	MULXQ (8*2)(x_ptr), AX, t1;\
	ADOXQ AX, acc3;\
	\
	MULXQ (8*3)(x_ptr), AX, acc5;\
	ADCXQ t1, AX;\
	ADOXQ AX, acc4;\
	ADCXQ y_ptr, acc5;\
	\
	\// y[3] * y[2]
	MOVQ (8*2)(x_ptr), DX;\
	MULXQ (8*3)(x_ptr), AX, y_ptr;\ 
	ADOXQ AX, acc5;\
	ADOXQ acc0, y_ptr;\
	\
	XORQ t1, t1;\
	\// *2
	ADOXQ acc1, acc1;\
	ADOXQ acc2, acc2;\
	ADOXQ acc3, acc3;\
	ADOXQ acc4, acc4;\
	ADOXQ acc5, acc5;\
	ADOXQ y_ptr, y_ptr;\
	ADOXQ acc0, t1;\
	\
	\// Missing products
	MOVQ (8*0)(x_ptr), DX;\
	MULXQ DX, acc0, t0;\
	ADCXQ t0, acc1;\
	\
	MOVQ (8*1)(x_ptr), DX;\
	MULXQ DX, AX, t0;\
	ADCXQ AX, acc2;\
	ADCXQ t0, acc3;\
	\
	MOVQ (8*2)(x_ptr), DX;\
	MULXQ DX, AX, t0 ;\
	ADCXQ AX, acc4;\
	ADCXQ t0, acc5;\
	\
	MOVQ (8*3)(x_ptr), DX;\
	MULXQ DX, AX, x_ptr;\
	ADCXQ AX, y_ptr;\
	ADCXQ t1, x_ptr;\
	\
	\// T = [x_ptr, y_ptr, acc5, acc4, acc3, acc2, acc1, acc0]
	\// First reduction step
	MOVQ acc0, DX;\
	MULXQ p256ordK0<>(SB), DX, AX;\
	\
	MULXQ p256ord<>+0x00(SB), AX, t0;\
	ADOXQ AX, acc0;\// (carry1, acc0) = acc0 + t0 * ord0
	\
	MULXQ p256ord<>+0x08(SB), AX, t1;\
	ADCXQ t0, AX;\
	ADOXQ AX, acc1;\
	\
	MULXQ p256ord<>+0x10(SB), AX, t0;\
	ADCXQ t1, AX;\
	ADOXQ AX, acc2;\
	\
	MULXQ p256ord<>+0x18(SB), AX, acc0;\
	ADCXQ t0, AX;\
	ADOXQ AX, acc3;\
	MOVQ $0, t0;\
	ADCXQ t0, acc0;\
	ADOXQ t0, acc0;\
	\
	\// Second reduction step
	MOVQ acc1, DX;\
	MULXQ p256ordK0<>(SB), DX, AX;\
	\
	MULXQ p256ord<>+0x00(SB), AX, t0;\
	ADOXQ AX, acc1;\
	\
	MULXQ p256ord<>+0x08(SB), AX, t1;\
	ADCXQ t0, AX;\
	ADOXQ AX, acc2;\
	\
	MULXQ p256ord<>+0x10(SB), AX, t0;\
	ADCXQ t1, AX;\
	ADOXQ AX, acc3;\
	\
	MULXQ p256ord<>+0x18(SB), AX, acc1;\
	ADCXQ t0, AX;\
	ADOXQ AX, acc0;\
	MOVQ $0, t0;\
	ADCXQ t0, acc1;\
	ADOXQ t0, acc1;\
	\
	\// Third reduction step
	MOVQ acc2, DX;\
	MULXQ p256ordK0<>(SB), DX, AX;\
	\
	MULXQ p256ord<>+0x00(SB), AX, t0;\
	ADOXQ AX, acc2;\
	\
	MULXQ p256ord<>+0x08(SB), AX, t1;\
	ADCXQ t0, AX;\
	ADOXQ AX, acc3;\
	\
	MULXQ p256ord<>+0x10(SB), AX, t0;\
	ADCXQ t1, AX;\
	ADOXQ AX, acc0;\
	\
	MULXQ p256ord<>+0x18(SB), AX, acc2;\
	ADCXQ t0, AX;\
	ADOXQ AX, acc1;\
	MOVQ $0, t0;\
	ADCXQ t0, acc2;\
	ADOXQ t0, acc2;\
	\
	\// Last reduction step
	MOVQ acc3, DX;\
	MULXQ p256ordK0<>(SB), DX, AX;\
	\
	MULXQ p256ord<>+0x00(SB), AX, t0;\
	ADOXQ AX, acc3;\
	\
	MULXQ p256ord<>+0x08(SB), AX, t1;\
	ADCXQ t0, AX;\
	ADOXQ AX, acc0;\
	\
	MULXQ p256ord<>+0x10(SB), AX, t0;\
	ADCXQ t1, AX;\
	ADOXQ AX, acc1;\
	\
	MULXQ p256ord<>+0x18(SB), AX, acc3;\
	ADCXQ t0, AX;\
	ADOXQ AX, acc2;\
	MOVQ $0, t0;\
	ADCXQ t0, acc3;\
	ADOXQ t0, acc3;\
	\
	XORQ t1, t1;\
	\// Add bits [511:256] of the sqr result
	ADCXQ acc4, acc0;\
	ADCXQ acc5, acc1;\
	ADCXQ y_ptr, acc2;\
	ADCXQ x_ptr, acc3;\
	ADCXQ t1, t0;\
	\
	p256OrdReduceInline(acc0, acc1, acc2, acc3, t0, acc4, acc5, y_ptr, t1, res_ptr);\
	MOVQ res_ptr, x_ptr;

// Below marcors are used for point operation
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
	CMOVQCS acc4, t0;\ // CMOVQCS: Move if below (CF == 1)
	CMOVQCS acc5, t1;\
	CMOVQCS acc6, t2;\
	CMOVQCS acc7, t3;

/* ---------------------------------------*/
// [acc7, acc6, acc5, acc4] = 2[acc7, acc6, acc5, acc4]
#define p256MulBy2Inline2\
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
	SUBQ $-1, acc4;\
	SBBQ p256p<>+0x08(SB), acc5;\
	SBBQ $-1, acc6;\
	SBBQ p256p<>+0x018(SB), acc7;\
	SBBQ $0, mul0;\
	CMOVQCS t0, acc4;\ // CMOVQCS: Move if below (CF == 1)
	CMOVQCS t1, acc5;\
	CMOVQCS t2, acc6;\
	CMOVQCS t3, acc7;

/* ---------------------------------------*/
// [t3, t2, t1, t0] = 3[acc7, acc6, acc5, acc4]
#define p256TripleInline\
	XORQ mul0, mul0;\
	MOVQ acc4, acc0;\
	MOVQ acc5, acc1;\
	MOVQ acc6, acc2;\
	MOVQ acc7, acc3;\
	ADDQ acc4, acc4;\
	ADCQ acc5, acc5;\
	ADCQ acc6, acc6;\
	ADCQ acc7, acc7;\
	ADCQ $0, mul0;\
	MOVQ acc4, t0;\
	MOVQ acc5, t1;\
	MOVQ acc6, t2;\
	MOVQ acc7, t3;\
	SUBQ $-1, acc4;\
	SBBQ p256p<>+0x08(SB), acc5;\
	SBBQ $-1, acc6;\
	SBBQ p256p<>+0x018(SB), acc7;\
	SBBQ $0, mul0;\
	CMOVQCS t0, acc4;\ // CMOVQCS: Move if below (CF == 1)
	CMOVQCS t1, acc5;\
	CMOVQCS t2, acc6;\
	CMOVQCS t3, acc7;\
	XORQ mul0, mul0;\
	ADDQ acc0, acc4;\
	ADCQ acc1, acc5;\
	ADCQ acc2, acc6;\
	ADCQ acc3, acc7;\
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
	CMOVQCS acc4, t0;\ // CMOVQCS: Move if below (CF == 1)
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
	CMOVQCS acc4, t0;\ // CMOVQCS: Move if below (CF == 1)
	CMOVQCS acc5, t1;\
	CMOVQCS acc6, t2;\
	CMOVQCS acc7, t3;

/* ---------------------------------------*/
// [t3, t2, t1, t0] = [acc7, acc6, acc5, acc4] - [t3, t2, t1, t0]
#define p256SubInline \
	XORQ mul0, mul0;\
	SUBQ t0, acc4;\
	SBBQ t1, acc5;\
	SBBQ t2, acc6;\
	SBBQ t3, acc7;\
	SBBQ $0, mul0;\
	MOVQ acc4, t0;\
	MOVQ acc5, t1;\
	MOVQ acc6, t2;\
	MOVQ acc7, t3;\
	ADDQ $-1, t0;\
	ADCQ p256p<>+0x08(SB), t1;\
	ADCQ $-1, t2;\
	ADCQ p256p<>+0x018(SB), t3;\
	ANDQ $1, mul0;\
	CMOVQEQ acc4, t0;\  // CMOVQEQ: Move if equal (ZF == 1)
	CMOVQEQ acc5, t1;\
	CMOVQEQ acc6, t2;\
	CMOVQEQ acc7, t3;\

/* ---------------------------------------*/
// [acc7, acc6, acc5, acc4] = [acc7, acc6, acc5, acc4] - [t3, t2, t1, t0]
#define p256SubInline2 \
	XORQ mul0, mul0;\
	SUBQ t0, acc4;\
	SBBQ t1, acc5;\
	SBBQ t2, acc6;\
	SBBQ t3, acc7;\
	SBBQ $0, mul0;\
	MOVQ acc4, acc0;\
	MOVQ acc5, acc1;\
	MOVQ acc6, acc2;\
	MOVQ acc7, acc3;\
	ADDQ $-1, acc4;\
	ADCQ p256p<>+0x08(SB), acc5;\
	ADCQ $-1, acc6;\
	ADCQ p256p<>+0x018(SB), acc7;\
	ANDQ $1, mul0;\
	CMOVQEQ acc0, acc4;\  // CMOVQEQ: Move if equal (ZF == 1)
	CMOVQEQ acc1, acc5;\
	CMOVQEQ acc2, acc6;\
	CMOVQEQ acc3, acc7;\

#define p256SqrInternalInline \
	MOVQ acc4, mul0;\
	MULQ acc5;\
	MOVQ mul0, acc1;\
	MOVQ mul1, acc2;\
	\
	MOVQ acc4, mul0;\
	MULQ acc6;\
	ADDQ mul0, acc2;\
	ADCQ $0, mul1;\
	MOVQ mul1, acc3;\
	\
	MOVQ acc4, mul0;\
	MULQ acc7;\
	ADDQ mul0, acc3;\
	ADCQ $0, mul1;\
	MOVQ mul1, t0;\
	\
	MOVQ acc5, mul0;\
	MULQ acc6;\
	ADDQ mul0, acc3;\
	ADCQ $0, mul1;\
	MOVQ mul1, acc0;\
	\
	MOVQ acc5, mul0;\
	MULQ acc7;\
	ADDQ acc0, t0;\
	ADCQ $0, mul1;\
	ADDQ mul0, t0;\
	ADCQ $0, mul1;\
	MOVQ mul1, t1;\
	\
	MOVQ acc6, mul0;\
	MULQ acc7;\
	ADDQ mul0, t1;\
	ADCQ $0, mul1;\
	MOVQ mul1, t2;\
	XORQ t3, t3;\
	\// *2
	ADDQ acc1, acc1;\
	ADCQ acc2, acc2;\
	ADCQ acc3, acc3;\
	ADCQ t0, t0;\
	ADCQ t1, t1;\
	ADCQ t2, t2;\
	ADCQ $0, t3;\
	\// Missing products
	MOVQ acc4, mul0;\
	MULQ mul0;\
	MOVQ mul0, acc0;\
	MOVQ mul1, acc4;\
	\
	MOVQ acc5, mul0;\
	MULQ mul0;\
	ADDQ acc4, acc1;\
	ADCQ mul0, acc2;\
	ADCQ $0, mul1;\
	MOVQ mul1, acc4;\
	\
	MOVQ acc6, mul0;\
	MULQ mul0;\
	ADDQ acc4, acc3;\
	ADCQ mul0, t0;\
	ADCQ $0, mul1;\
	MOVQ mul1, acc4;\
	\
	MOVQ acc7, mul0;\
	MULQ mul0;\
	ADDQ acc4, t1;\
	ADCQ mul0, t2;\
	ADCQ mul1, t3;\
	\// T = [t3, t2,, t1, t0, acc3, acc2, acc1, acc0]
	sm2P256SqrReductionInline;

#define p256SqrInternalInlineAdx \
	XORQ acc0, acc0;\
	XORQ t2, t2;\
	MOVQ acc4, mul1;\
	MULXQ acc5, acc1, acc2;\
	\
	MULXQ acc6, mul0, acc3;\
	ADOXQ mul0, acc2;\
	\
	MULXQ acc7, mul0, t0;\
	ADOXQ mul0, acc3;\
	ADOXQ t2, t0;\
	\
	MOVQ acc5, mul1;\
	MULXQ acc6, mul0, t3;\
	ADOXQ mul0, acc3;\
	\
	MULXQ acc7, mul0, t1;\
	ADCXQ t3, mul0;\
	ADOXQ mul0, t0;\
	ADCXQ t2, t1;\
	\
	MOVQ acc6, mul1;\
	MULXQ acc7, mul0, t2;\
	ADOXQ mul0, t1;\
	ADOXQ acc0, t2;\
	XORQ t3, t3;\
	\
	\// *2
	ADOXQ acc1, acc1;\
	ADOXQ acc2, acc2;\
	ADOXQ acc3, acc3;\
	ADOXQ t0, t0;\
	ADOXQ t1, t1;\
	ADOXQ t2, t2;\
	ADOXQ acc0, t3;\
	\
	\// Missing products
	MOVQ acc4, mul1;\
	MULXQ mul1, acc0, acc4;\ 
	ADDQ acc4, acc1;\
	\
	MOVQ acc5, mul1;\
	MULXQ mul1, mul0, acc4;\
	ADCXQ mul0, acc2;\
	ADCXQ acc4, acc3;\
	\
	MOVQ acc6, mul1;\
	MULXQ mul1, mul0, acc4;\
	ADCXQ mul0, t0;\
	ADCXQ acc4, t1;\
	\
	MOVQ acc7, mul1;\
	MULXQ mul1, mul0, acc4;\
	ADCXQ mul0, t2;\
	ADCXQ acc4, t3;\
	\// T = [t3, t2,, t1, t0, acc3, acc2, acc1, acc0]
	sm2P256SqrReductionInline;

// p256IsZeroInline returns 1 in AX if [acc4..acc7] represents zero and zero
// otherwise. It writes to [acc4..acc7], t0 and t1.
#define p256IsZeroInline \
	\// AX contains a flag that is set if the input is zero.
	XORQ AX, AX;\
	MOVQ $1, t1;\
	\// Check whether [acc4..acc7] are all zero.
	MOVQ acc4, t0;\
	ORQ acc5, t0;\
	ORQ acc6, t0;\
	ORQ acc7, t0;\
	\// Set the zero flag if so. (CMOV of a constant to a register doesn't
	\// appear to be supported in Go. Thus t1 = 1.)
	CMOVQEQ t1, AX;\  // CMOVQEQ: Move if equal (ZF == 1)
	\// XOR [acc4..acc7] with P and compare with zero again.
	XORQ $-1, acc4;\
	XORQ p256p<>+0x08(SB), acc5;\
	XORQ $-1, acc6;\
	XORQ p256p<>+0x018(SB), acc7;\
	ORQ acc5, acc4;\
	ORQ acc6, acc4;\
	ORQ acc7, acc4;\
	\// Set the zero flag if so.
	\// CMOVQEQ: Move if equal (ZF == 1)
	CMOVQEQ t1, AX;

#define p256PointDoubleInit() \
	MOVOU (16*0)(BX), X0;\
	MOVOU (16*1)(BX), X1;\
	MOVOU (16*2)(BX), X2;\
	MOVOU (16*3)(BX), X3;\
	MOVOU (16*4)(BX), X4;\
	MOVOU (16*5)(BX), X5;\
	\
	MOVOU X0, x(16*0);\
	MOVOU X1, x(16*1);\
	MOVOU X2, y(16*0);\
	MOVOU X3, y(16*1);\
	MOVOU X4, z(16*0);\
	MOVOU X5, z(16*1);
