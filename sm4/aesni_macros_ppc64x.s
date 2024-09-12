#define LOAD_CONSTS(baseAddrReg, offsetReg) \
	LXVD2X (baseAddrReg)(R0), M0; \
	MOVD $0x10, offsetReg; \
	LXVD2X (baseAddrReg)(offsetReg), M1; \
	MOVD $0x20, offsetReg; \
	LXVD2X (baseAddrReg)(offsetReg), M2; \
	MOVD $0x30, offsetReg; \
	LXVD2X (baseAddrReg)(offsetReg), M3; \
	MOVD $0x40, offsetReg; \
	LXVD2X (baseAddrReg)(offsetReg), REVERSE_WORDS; \
	MOVD $0x50, offsetReg; \
	LXVD2X (baseAddrReg)(offsetReg), NIBBLE_MASK; \
	MOVD $0x60, offsetReg; \
	LXVD2X (baseAddrReg)(offsetReg), INVERSE_SHIFT_ROWS; \
	MOVD $0x70, offsetReg; \
	LXVD2X (baseAddrReg)(offsetReg), M1L; \
	MOVD $0x80, offsetReg; \
	LXVD2X (baseAddrReg)(offsetReg), M1H; \
	MOVD $0x90, offsetReg; \
	LXVD2X (baseAddrReg)(offsetReg), M2L; \
	MOVD $0xa0, offsetReg; \
	LXVD2X (baseAddrReg)(offsetReg), M2H

#ifdef GOARCH_ppc64le
#define NEEDS_PERMW

#define PPC64X_LXVW4X(RA,RB,VT) \
	LXVW4X	(RA+RB), VT \
	VPERM	VT, VT, ESPERMW, VT

#define PPC64X_STXVW4X(VS, RA, RB) \
	VPERM	VS, VS, ESPERMW, VS \
	STXVW4X	VS, (RA+RB)

#else
#define PPC64X_LXVW4X(RA,RB,VT)  LXVW4X	(RA+RB), VT
#define PPC64X_STXVW4X(VS, RA, RB) STXVW4X	VS, (RA+RB)
#endif // defined(GOARCH_ppc64le)

// r = s <<< n
// Due to VSPLTISW's limitation, the n MUST be [0, 15],
// If n > 15, we have to call it multiple times.
// VSPLTISW takes a 5-bit immediate value as an operand.
// I also did NOT find one vector instruction to use immediate value for ROTL.
#define PROLD(s, r, tmp, n) \
	VSPLTISW $n, tmp \
	VRLW	s, tmp, r

// input: from high to low
// t0 = t0.S3, t0.S2, t0.S1, t0.S0
// t1 = t1.S3, t1.S2, t1.S1, t1.S0
// t2 = t2.S3, t2.S2, t2.S1, t2.S0
// t3 = t3.S3, t3.S2, t3.S1, t3.S0
// output: from high to low
// t0 = t3.S0, t2.S0, t1.S0, t0.S0
// t1 = t3.S1, t2.S1, t1.S1, t0.S1
// t2 = t3.S2, t2.S2, t1.S2, t0.S2
// t3 = t3.S3, t2.S3, t1.S3, t0.S3
#define PRE_TRANSPOSE_MATRIX(T0, T1, T2, T3) \
	VPERM T0, T1, M0, TMP0; \
	VPERM T2, T3, M0, TMP1; \
	VPERM T0, T1, M1, TMP2; \
	VPERM T2, T3, M1, TMP3; \
	VPERM TMP0, TMP1, M2, T0; \
	VPERM TMP0, TMP1, M3, T1; \
	VPERM TMP2, TMP3, M2, T2; \
	VPERM TMP2, TMP3, M3, T3

// input: from high to low
// t0 = t0.S3, t0.S2, t0.S1, t0.S0
// t1 = t1.S3, t1.S2, t1.S1, t1.S0
// t2 = t2.S3, t2.S2, t2.S1, t2.S0
// t3 = t3.S3, t3.S2, t3.S1, t3.S0
// output: from high to low
// t0 = t0.S0, t1.S0, t2.S0, t3.S0
// t1 = t0.S1, t1.S1, t2.S1, t3.S1
// t2 = t0.S2, t1.S2, t2.S2, t3.S2
// t3 = t0.S3, t1.S3, t2.S3, t3.S3
#define TRANSPOSE_MATRIX(T0, T1, T2, T3) \
	VPERM T1, T0, M0, TMP0; \
	VPERM T1, T0, M1, TMP1; \
	VPERM T3, T2, M0, TMP2; \
	VPERM T3, T2, M1, TMP3; \
	VPERM TMP2, TMP0, M2, T0; \
	VPERM TMP2, TMP0, M3, T1; \
	VPERM TMP3, TMP1, M2, T2; \
	VPERM TMP3, TMP1, M3, T3; \	

// Affine Transform
// parameters:
// -  L: table low nibbles
// -  H: table high nibbles
// -  x: 128 bits register as sbox input/output data
// -  y: 128 bits temp register
// -  z: 128 bits temp register
#define AFFINE_TRANSFORM(L, H, V_FOUR, x, y, z)  \
	VAND NIBBLE_MASK, x, z;              \
	VPERM L, L, z, y;                    \
	VSRD x, V_FOUR, x;                   \
	VAND NIBBLE_MASK, x, z;              \
	VPERM H, H, z, x;                    \
	VXOR y, x, x

// Affine Transform
// parameters:
// -  L: table low nibbles
// -  H: table high nibbles
// -  x: 128 bits register as sbox input/output data
// -  y: 128 bits temp register
// -  z: 128 bits temp register
#define AFFINE_TRANSFORM_NOTX(L, H, V_FOUR, x, y, z)  \
	VNOR  x, x, z;                       \ // z = NOT(x)
	VAND  NIBBLE_MASK, z, z;             \	
	VPERM L, L, z, y;                    \
	VSRD x, V_FOUR, x;                   \
	VAND NIBBLE_MASK, x, z;              \
	VPERM H, H, z, x;                    \
	VXOR y, x, x

// SM4 sbox function
// parameters:
// -  x: 128 bits register as sbox input/output data
// -  y: 128 bits temp register
// -  z: 128 bits temp register
#define SM4_SBOX(x, y, z) \
	AFFINE_TRANSFORM(M1L, M1H, V_FOUR, x, y, z); \
	VPERM x, x, INVERSE_SHIFT_ROWS, x;           \
	VCIPHERLAST x, NIBBLE_MASK, x;               \
	AFFINE_TRANSFORM_NOTX(M2L, M2H, V_FOUR, x, y, z)

// SM4 TAO L1 function
// parameters:
// -  x: 128 bits register as TAO_L1 input/output data
// -  tmp1: 128 bits temp register
// -  tmp2: 128 bits temp register
// -  tmp3: 128 bits temp register
#define SM4_TAO_L1(x, tmp1, tmp2, tmp3)         \
	SM4_SBOX(x, tmp1, tmp2);                      \
	;                                       \ //####################  4 parallel L1 linear transforms ##################//
	VSPLTISW $8, tmp3;                      \
	VRLW	x, tmp3, tmp1;                  \ // tmp1 = x <<< 8
	VRLW tmp1, tmp3, tmp2;                  \ // tmp2 = x <<< 16
	VXOR x, tmp1, tmp1;                     \ // tmp1 = x xor (x <<< 8)
	VXOR tmp1, tmp2, tmp1;                  \ // tmp1 = x xor (x <<< 8) xor (x <<< 16)
	VRLW tmp2, tmp3, tmp2;                  \ // tmp2 = x <<< 24
	VXOR tmp2, x, x;                        \ // x = x xor (x <<< 24)
	VSPLTISW $2, tmp3;                      \
	VRLW tmp1, tmp3, tmp1;                  \ // tmp1 = (x xor (x <<< 8) xor (x <<< 16)) <<< 2
	VXOR tmp1, x, x

// SM4 round function
// t0 ^= tao_l1(t1^t2^t3^xk)
// parameters:
// - RK: round key register
// -  x: 128 bits temp register
// - tmp1: 128 bits temp register
// - tmp2: 128 bits temp register
// - tmp3: 128 bits temp register
// - t0: 128 bits register for data as result
// - t1: 128 bits register for data
// - t2: 128 bits register for data
// - t3: 128 bits register for data
#define SM4_ROUND(RK, x, tmp1, tmp2, tmp3, t0, t1, t2, t3) \ 
	VXOR RK, t1, x;					  \
	VXOR t2, x, x;					  \
	VXOR t3, x, x;					  \
	SM4_TAO_L1(x, tmp1, tmp2, tmp3);  \
	VXOR x, t0, t0

#define PROCESS_8BLOCKS_4ROUND \
	VSPLTW $0, V8, V9; \
	SM4_ROUND(V9, TMP0, TMP1, TMP2, TMP3, V0, V1, V2, V3); \
	SM4_ROUND(V9, TMP0, TMP1, TMP2, TMP3, V4, V5, V6, V7); \
	VSPLTW $1, V8, V9; \
	SM4_ROUND(V9, TMP0, TMP1, TMP2, TMP3, V1, V2, V3, V0); \
	SM4_ROUND(V9, TMP0, TMP1, TMP2, TMP3, V5, V6, V7, V4); \
	VSPLTW $2, V8, V9; \
	SM4_ROUND(V9, TMP0, TMP1, TMP2, TMP3, V2, V3, V0, V1); \
	SM4_ROUND(V9, TMP0, TMP1, TMP2, TMP3, V6, V7, V4, V5); \
	VSPLTW $3, V8, V9; \
	SM4_ROUND(V9, TMP0, TMP1, TMP2, TMP3, V3, V0, V1, V2); \
	SM4_ROUND(V9, TMP0, TMP1, TMP2, TMP3, V7, V4, V5, V6)

#define PROCESS_4BLOCKS_4ROUND \
	VSPLTW $0, V8, V9; \
	SM4_ROUND(V9, TMP0, TMP1, TMP2, TMP3, V0, V1, V2, V3); \
	VSPLTW $1, V8, V9; \
	SM4_ROUND(V9, TMP0, TMP1, TMP2, TMP3, V1, V2, V3, V0); \
	VSPLTW $2, V8, V9; \
	SM4_ROUND(V9, TMP0, TMP1, TMP2, TMP3, V2, V3, V0, V1); \
	VSPLTW $3, V8, V9; \
	SM4_ROUND(V9, TMP0, TMP1, TMP2, TMP3, V3, V0, V1, V2)

#define PROCESS_SINGLEBLOCK_4ROUND \
	SM4_ROUND(V8, TMP0, TMP1, TMP2, TMP3, V0, V1, V2, V3); \
	VSLDOI $4, V8, V8, V8; \
	SM4_ROUND(V8, TMP0, TMP1, TMP2, TMP3, V1, V2, V3, V0); \
	VSLDOI $4, V8, V8, V8; \
	SM4_ROUND(V8, TMP0, TMP1, TMP2, TMP3, V2, V3, V0, V1); \
	VSLDOI $4, V8, V8, V8; \
	SM4_ROUND(V8, TMP0, TMP1, TMP2, TMP3, V3, V0, V1, V2)
