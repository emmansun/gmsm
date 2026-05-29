// SM4 GFNI implementation - uses GF2P8AFFINEQB/GF2P8AFFINEINVQB for S-box
// Requires: AVX2 + GFNI (CPUID.07H:ECX[bit 8])
// Reference: .github/skills/sm4-gfni/SKILL.md

// GFNI SM4 S-box: 2 instructions replacing ~20 AES-NI instructions
// SM4_Sbox(x) = M_post · Inv(M_pre · x ⊕ c_pre) ⊕ c_post
// parameters:
// - x: 256-bit register (input/output, 32 bytes of S-box data)
// - preMatrix: 256-bit register with pre-affine matrix (broadcast uint64)
// - postMatrix: 256-bit register with post-affine matrix (broadcast uint64)
#define GFNI_SM4_SBOX(x, preMatrix, postMatrix) \
	VGF2P8AFFINEQB $0x69, preMatrix, x, x;     \
	VGF2P8AFFINEINVQB $0xd3, postMatrix, x, x

// GFNI SM4 TAO L1 function (S-box + L linear transform), AVX2 version
// parameters:
// - x: 256-bit register (input/output)
// - y: 256-bit temp register
// - z: 256-bit temp register
// - preMatrix: 256-bit register with pre-affine matrix
// - postMatrix: 256-bit register with post-affine matrix
#define GFNI_SM4_TAO_L1(x, y, z, preMatrix, postMatrix) \
	GFNI_SM4_SBOX(x, preMatrix, postMatrix);            \
	VPSHUFB ·r08_mask(SB), x, y;                        \ // y = x <<< 8
	VPSHUFB ·r08_mask(SB), y, z;                        \ // z = x <<< 16
	VPXOR x, y, y;                                      \ // y = x ^ (x <<< 8)
	VPXOR z, y, y;                                      \ // y = x ^ (x <<< 8) ^ (x <<< 16)
	VPSHUFB ·r08_mask(SB), z, z;                        \ // z = x <<< 24
	VPXOR x, z, x;                                      \ // x = x ^ (x <<< 24)
	VPSLLD $2, y, z;                                    \
	VPSRLD $30, y, y;                                   \
	VPOR z, y, y;                                       \ // y = (x ^ (x<<<8) ^ (x<<<16)) <<< 2
	VPXOR y, x, x

// GFNI SM4 round function, AVX2 version, 256-bit (8 parallel blocks)
// t0 ^= tao_l1(t1^t2^t3^rk)
// parameters:
// - index: round key index
// - RK: round key base register
// - x: 256-bit temp register
// - y: 256-bit temp register
// - z: 256-bit temp register
// - preMatrix: pre-affine matrix register
// - postMatrix: post-affine matrix register
// - t0, t1, t2, t3: 256-bit data registers
#define GFNI_SM4_ROUND(index, RK, x, y, z, preMatrix, postMatrix, t0, t1, t2, t3) \
	VPBROADCASTD (index * 4)(RK), x;                                               \
	VPXOR t1, x, x;                                                                \
	VPXOR t2, x, x;                                                                \
	VPXOR t3, x, x;                                                                \
	GFNI_SM4_TAO_L1(x, y, z, preMatrix, postMatrix);                               \
	VPXOR x, t0, t0

// GFNI SM4 8 blocks encryption (32 rounds)
// parameters:
// - RK: round key base register
// - x, y, z: temp registers
// - preMatrix, postMatrix: constant matrix registers
// - t0, t1, t2, t3: data registers
#define GFNI_SM4_8BLOCKS(RK, x, y, z, preMatrix, postMatrix, t0, t1, t2, t3) \
	GFNI_SM4_ROUND(0, RK, x, y, z, preMatrix, postMatrix, t0, t1, t2, t3);  \
	GFNI_SM4_ROUND(1, RK, x, y, z, preMatrix, postMatrix, t1, t2, t3, t0);  \
	GFNI_SM4_ROUND(2, RK, x, y, z, preMatrix, postMatrix, t2, t3, t0, t1);  \
	GFNI_SM4_ROUND(3, RK, x, y, z, preMatrix, postMatrix, t3, t0, t1, t2);  \
	GFNI_SM4_ROUND(4, RK, x, y, z, preMatrix, postMatrix, t0, t1, t2, t3);  \
	GFNI_SM4_ROUND(5, RK, x, y, z, preMatrix, postMatrix, t1, t2, t3, t0);  \
	GFNI_SM4_ROUND(6, RK, x, y, z, preMatrix, postMatrix, t2, t3, t0, t1);  \
	GFNI_SM4_ROUND(7, RK, x, y, z, preMatrix, postMatrix, t3, t0, t1, t2);  \
	GFNI_SM4_ROUND(8, RK, x, y, z, preMatrix, postMatrix, t0, t1, t2, t3);  \
	GFNI_SM4_ROUND(9, RK, x, y, z, preMatrix, postMatrix, t1, t2, t3, t0);  \
	GFNI_SM4_ROUND(10, RK, x, y, z, preMatrix, postMatrix, t2, t3, t0, t1); \
	GFNI_SM4_ROUND(11, RK, x, y, z, preMatrix, postMatrix, t3, t0, t1, t2); \
	GFNI_SM4_ROUND(12, RK, x, y, z, preMatrix, postMatrix, t0, t1, t2, t3); \
	GFNI_SM4_ROUND(13, RK, x, y, z, preMatrix, postMatrix, t1, t2, t3, t0); \
	GFNI_SM4_ROUND(14, RK, x, y, z, preMatrix, postMatrix, t2, t3, t0, t1); \
	GFNI_SM4_ROUND(15, RK, x, y, z, preMatrix, postMatrix, t3, t0, t1, t2); \
	GFNI_SM4_ROUND(16, RK, x, y, z, preMatrix, postMatrix, t0, t1, t2, t3); \
	GFNI_SM4_ROUND(17, RK, x, y, z, preMatrix, postMatrix, t1, t2, t3, t0); \
	GFNI_SM4_ROUND(18, RK, x, y, z, preMatrix, postMatrix, t2, t3, t0, t1); \
	GFNI_SM4_ROUND(19, RK, x, y, z, preMatrix, postMatrix, t3, t0, t1, t2); \
	GFNI_SM4_ROUND(20, RK, x, y, z, preMatrix, postMatrix, t0, t1, t2, t3); \
	GFNI_SM4_ROUND(21, RK, x, y, z, preMatrix, postMatrix, t1, t2, t3, t0); \
	GFNI_SM4_ROUND(22, RK, x, y, z, preMatrix, postMatrix, t2, t3, t0, t1); \
	GFNI_SM4_ROUND(23, RK, x, y, z, preMatrix, postMatrix, t3, t0, t1, t2); \
	GFNI_SM4_ROUND(24, RK, x, y, z, preMatrix, postMatrix, t0, t1, t2, t3); \
	GFNI_SM4_ROUND(25, RK, x, y, z, preMatrix, postMatrix, t1, t2, t3, t0); \
	GFNI_SM4_ROUND(26, RK, x, y, z, preMatrix, postMatrix, t2, t3, t0, t1); \
	GFNI_SM4_ROUND(27, RK, x, y, z, preMatrix, postMatrix, t3, t0, t1, t2); \
	GFNI_SM4_ROUND(28, RK, x, y, z, preMatrix, postMatrix, t0, t1, t2, t3); \
	GFNI_SM4_ROUND(29, RK, x, y, z, preMatrix, postMatrix, t1, t2, t3, t0); \
	GFNI_SM4_ROUND(30, RK, x, y, z, preMatrix, postMatrix, t2, t3, t0, t1); \
	GFNI_SM4_ROUND(31, RK, x, y, z, preMatrix, postMatrix, t3, t0, t1, t2)

// GFNI SM4 16 blocks round function
// Applies one round to two sets of 4 YMM registers (8+8=16 blocks)
#define GFNI_SM4_16BLOCKS_ROUND(index, RK, x, y, z, preMatrix, postMatrix, t0, t1, t2, t3, t4, t5, t6, t7) \
	VPBROADCASTD (index * 4)(RK), x;                                                                        \
	VPXOR t1, x, y;                                                                                         \
	VPXOR t2, y, y;                                                                                         \
	VPXOR t3, y, y;                                                                                         \
	GFNI_SM4_TAO_L1(y, z, x, preMatrix, postMatrix);                                                        \
	VPXOR y, t0, t0;                                                                                        \
	VPBROADCASTD (index * 4)(RK), x;                                                                        \
	VPXOR t5, x, y;                                                                                         \
	VPXOR t6, y, y;                                                                                         \
	VPXOR t7, y, y;                                                                                         \
	GFNI_SM4_TAO_L1(y, z, x, preMatrix, postMatrix);                                                        \
	VPXOR y, t4, t4

// GFNI SM4 16 blocks encryption (32 rounds)
#define GFNI_SM4_16BLOCKS(RK, x, y, z, preMatrix, postMatrix, t0, t1, t2, t3, t4, t5, t6, t7) \
	GFNI_SM4_16BLOCKS_ROUND(0, RK, x, y, z, preMatrix, postMatrix, t0, t1, t2, t3, t4, t5, t6, t7);  \
	GFNI_SM4_16BLOCKS_ROUND(1, RK, x, y, z, preMatrix, postMatrix, t1, t2, t3, t0, t5, t6, t7, t4);  \
	GFNI_SM4_16BLOCKS_ROUND(2, RK, x, y, z, preMatrix, postMatrix, t2, t3, t0, t1, t6, t7, t4, t5);  \
	GFNI_SM4_16BLOCKS_ROUND(3, RK, x, y, z, preMatrix, postMatrix, t3, t0, t1, t2, t7, t4, t5, t6);  \
	GFNI_SM4_16BLOCKS_ROUND(4, RK, x, y, z, preMatrix, postMatrix, t0, t1, t2, t3, t4, t5, t6, t7);  \
	GFNI_SM4_16BLOCKS_ROUND(5, RK, x, y, z, preMatrix, postMatrix, t1, t2, t3, t0, t5, t6, t7, t4);  \
	GFNI_SM4_16BLOCKS_ROUND(6, RK, x, y, z, preMatrix, postMatrix, t2, t3, t0, t1, t6, t7, t4, t5);  \
	GFNI_SM4_16BLOCKS_ROUND(7, RK, x, y, z, preMatrix, postMatrix, t3, t0, t1, t2, t7, t4, t5, t6);  \
	GFNI_SM4_16BLOCKS_ROUND(8, RK, x, y, z, preMatrix, postMatrix, t0, t1, t2, t3, t4, t5, t6, t7);  \
	GFNI_SM4_16BLOCKS_ROUND(9, RK, x, y, z, preMatrix, postMatrix, t1, t2, t3, t0, t5, t6, t7, t4);  \
	GFNI_SM4_16BLOCKS_ROUND(10, RK, x, y, z, preMatrix, postMatrix, t2, t3, t0, t1, t6, t7, t4, t5); \
	GFNI_SM4_16BLOCKS_ROUND(11, RK, x, y, z, preMatrix, postMatrix, t3, t0, t1, t2, t7, t4, t5, t6); \
	GFNI_SM4_16BLOCKS_ROUND(12, RK, x, y, z, preMatrix, postMatrix, t0, t1, t2, t3, t4, t5, t6, t7); \
	GFNI_SM4_16BLOCKS_ROUND(13, RK, x, y, z, preMatrix, postMatrix, t1, t2, t3, t0, t5, t6, t7, t4); \
	GFNI_SM4_16BLOCKS_ROUND(14, RK, x, y, z, preMatrix, postMatrix, t2, t3, t0, t1, t6, t7, t4, t5); \
	GFNI_SM4_16BLOCKS_ROUND(15, RK, x, y, z, preMatrix, postMatrix, t3, t0, t1, t2, t7, t4, t5, t6); \
	GFNI_SM4_16BLOCKS_ROUND(16, RK, x, y, z, preMatrix, postMatrix, t0, t1, t2, t3, t4, t5, t6, t7); \
	GFNI_SM4_16BLOCKS_ROUND(17, RK, x, y, z, preMatrix, postMatrix, t1, t2, t3, t0, t5, t6, t7, t4); \
	GFNI_SM4_16BLOCKS_ROUND(18, RK, x, y, z, preMatrix, postMatrix, t2, t3, t0, t1, t6, t7, t4, t5); \
	GFNI_SM4_16BLOCKS_ROUND(19, RK, x, y, z, preMatrix, postMatrix, t3, t0, t1, t2, t7, t4, t5, t6); \
	GFNI_SM4_16BLOCKS_ROUND(20, RK, x, y, z, preMatrix, postMatrix, t0, t1, t2, t3, t4, t5, t6, t7); \
	GFNI_SM4_16BLOCKS_ROUND(21, RK, x, y, z, preMatrix, postMatrix, t1, t2, t3, t0, t5, t6, t7, t4); \
	GFNI_SM4_16BLOCKS_ROUND(22, RK, x, y, z, preMatrix, postMatrix, t2, t3, t0, t1, t6, t7, t4, t5); \
	GFNI_SM4_16BLOCKS_ROUND(23, RK, x, y, z, preMatrix, postMatrix, t3, t0, t1, t2, t7, t4, t5, t6); \
	GFNI_SM4_16BLOCKS_ROUND(24, RK, x, y, z, preMatrix, postMatrix, t0, t1, t2, t3, t4, t5, t6, t7); \
	GFNI_SM4_16BLOCKS_ROUND(25, RK, x, y, z, preMatrix, postMatrix, t1, t2, t3, t0, t5, t6, t7, t4); \
	GFNI_SM4_16BLOCKS_ROUND(26, RK, x, y, z, preMatrix, postMatrix, t2, t3, t0, t1, t6, t7, t4, t5); \
	GFNI_SM4_16BLOCKS_ROUND(27, RK, x, y, z, preMatrix, postMatrix, t3, t0, t1, t2, t7, t4, t5, t6); \
	GFNI_SM4_16BLOCKS_ROUND(28, RK, x, y, z, preMatrix, postMatrix, t0, t1, t2, t3, t4, t5, t6, t7); \
	GFNI_SM4_16BLOCKS_ROUND(29, RK, x, y, z, preMatrix, postMatrix, t1, t2, t3, t0, t5, t6, t7, t4); \
	GFNI_SM4_16BLOCKS_ROUND(30, RK, x, y, z, preMatrix, postMatrix, t2, t3, t0, t1, t6, t7, t4, t5); \
	GFNI_SM4_16BLOCKS_ROUND(31, RK, x, y, z, preMatrix, postMatrix, t3, t0, t1, t2, t7, t4, t5, t6)
