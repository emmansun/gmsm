#define LOAD_CONSTS(baseAddrReg, offsetReg) \
	LXVD2X (baseAddrReg)(R0), REVERSE_WORDS; \
	MOVD $0x10, offsetReg; \
	LXVD2X (baseAddrReg)(offsetReg), M1L; \
	MOVD $0x20, offsetReg; \
	LXVD2X (baseAddrReg)(offsetReg), M1H; \
	MOVD $0x30, offsetReg; \
	LXVD2X (baseAddrReg)(offsetReg), M2L; \
	MOVD $0x40, offsetReg; \
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
	VMRGEW T0, T1, TMP0; \
	VMRGEW T2, T3, TMP1; \
	VMRGOW T0, T1, TMP2; \
	VMRGOW T2, T3, TMP3; \
	XXPERMDI TMP0, TMP1, $0, T0; \
	XXPERMDI TMP0, TMP1, $3, T2; \
	XXPERMDI TMP2, TMP3, $0, T1; \
	XXPERMDI TMP2, TMP3, $3, T3

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
	VMRGEW T1, T0, TMP0; \
	VMRGEW T3, T2, TMP1; \
	VMRGOW T1, T0, TMP2; \
	VMRGOW T3, T2, TMP3; \
	XXPERMDI TMP1, TMP0, $0, T0; \
	XXPERMDI TMP1, TMP0, $3, T2; \
	XXPERMDI TMP3, TMP2, $0, T1; \
	XXPERMDI TMP3, TMP2, $3, T3

// SM4 sbox function
// parameters:
// -  x: 128 bits register as sbox input/output data
#define SM4_SBOX(x)                    \
	VPERMXOR M1H, M1L, x, x;           \
	VSBOX x, x;                        \
	VPERMXOR M2H, M2L, x, x

// SM4 TAO L1 function
// parameters:
// -  x: 128 bits register as TAO_L1 input/output data
// -  tmp1: 128 bits temp register
// -  tmp2: 128 bits temp register
// -  tmp3: 128 bits temp register
#define SM4_TAO_L1(x, tmp1, tmp2, tmp3)     \
	SM4_SBOX(x);                            \
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
