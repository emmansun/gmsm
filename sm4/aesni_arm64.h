//nibble mask
DATA nibble_mask<>+0x00(SB)/8, $0x0F0F0F0F0F0F0F0F
DATA nibble_mask<>+0x08(SB)/8, $0x0F0F0F0F0F0F0F0F
GLOBL nibble_mask<>(SB), (NOPTR+RODATA), $16

// inverse shift rows
DATA inverse_shift_rows<>+0x00(SB)/8, $0x0B0E0104070A0D00
DATA inverse_shift_rows<>+0x08(SB)/8, $0x0306090C0F020508 
GLOBL inverse_shift_rows<>(SB), (NOPTR+RODATA), $16

// Affine transform 1 (low and high hibbles)
DATA m1_low<>+0x00(SB)/8, $0x0A7FC3B6D5A01C69
DATA m1_low<>+0x08(SB)/8, $0x3045F98CEF9A2653
GLOBL m1_low<>(SB), (NOPTR+RODATA), $16

DATA m1_high<>+0x00(SB)/8, $0xC35BF46CAF379800
DATA m1_high<>+0x08(SB)/8, $0x68F05FC7049C33AB  
GLOBL m1_high<>(SB), (NOPTR+RODATA), $16

// Affine transform 2 (low and high hibbles)
DATA m2_low<>+0x00(SB)/8, $0x9A950A05FEF16E61
DATA m2_low<>+0x08(SB)/8, $0x0E019E916A65FAF5
GLOBL m2_low<>(SB), (NOPTR+RODATA), $16

DATA m2_high<>+0x00(SB)/8, $0x892D69CD44E0A400
DATA m2_high<>+0x08(SB)/8, $0x2C88CC68E14501A5
GLOBL m2_high<>(SB), (NOPTR+RODATA), $16

// left rotations of 32-bit words by 8-bit increments
DATA r08_mask<>+0x00(SB)/8, $0x0605040702010003
DATA r08_mask<>+0x08(SB)/8, $0x0E0D0C0F0A09080B  
GLOBL r08_mask<>(SB), (NOPTR+RODATA), $16

DATA r16_mask<>+0x00(SB)/8, $0x0504070601000302
DATA r16_mask<>+0x08(SB)/8, $0x0D0C0F0E09080B0A   
GLOBL r16_mask<>(SB), (NOPTR+RODATA), $16

DATA r24_mask<>+0x00(SB)/8, $0x0407060500030201
DATA r24_mask<>+0x08(SB)/8, $0x0C0F0E0D080B0A09  
GLOBL r24_mask<>(SB), (NOPTR+RODATA), $16

DATA fk_mask<>+0x00(SB)/8, $0x56aa3350a3b1bac6
DATA fk_mask<>+0x08(SB)/8, $0xb27022dc677d9197
GLOBL fk_mask<>(SB), (NOPTR+RODATA), $16

#define PRE_TRANSPOSE_MATRIX(t0, t1, t2, t3, K) \
	VMOV t0.B16, K.B16                         \
	VMOV t1.S[0], t0.S[1]                      \
	VMOV t2.S[0], t0.S[2]                      \
	VMOV t3.S[0], t0.S[3]                      \
	VMOV K.S[1], t1.S[0]                       \
	VMOV K.S[2], t2.S[0]                       \
	VMOV K.S[3], t3.S[0]                       \
	VMOV t1.D[1], K.D[1]                       \
	VMOV t2.S[1], t1.S[2]                      \
	VMOV t3.S[1], t1.S[3]                      \
	VMOV K.S[2], t2.S[1]                       \
	VMOV K.S[3], t3.S[1]                       \
	VMOV t2.S[3], K.S[3]                       \
	VMOV t3.S[2], t2.S[3]                      \
	VMOV K.S[3], t3.S[2]

#define TRANSPOSE_MATRIX(t0, t1, t2, t3, K) \
	VMOV t0.B16, K.B16                        \
	VMOV t3.S[0], t0.S[0]                     \   
	VMOV t2.S[0], t0.S[1]                     \
	VMOV t1.S[0], t0.S[2]                     \
	VMOV K0.S[0], t0.S[3]                     \
	VMOV t3.S[1], t1.S[0]                     \
	VMOV t3.S[2], t2.S[0]                     \
	VMOV t3.S[3], t3.S[0]                     \
	VMOV t2.S[3], t3.S[1]                     \
	VMOV t1.S[3], t3.S[2]                     \
	VMOV K.S[3], t3.S[3]                      \
	VMOV K.S[2], t2.S[3]                      \
	VMOV K.S[1], t1.S[3]                      \
	VMOV t1.B16, K.B16                        \
	VMOV t2.S[1], t1.S[1]                     \
	VMOV K.S[1], t1.S[2]                      \
	VMOV t2.S[2], t2.S[1]                     \
	VMOV K.S[2], t2.S[2]

#define SM4_SBOX(x, y, z) \
  ;                                              \
  VAND x.B16, NIBBLE_MASK.B16, z.B16;            \
  VTBL z.B16, [M1L.B16], y.B16;                  \
  VUSHR $4, x.D2, x.D2;                          \
  VAND x.B16, NIBBLE_MASK.B16, z.B16;            \
  VTBL z.B16, [M1H.B16], z.B16;                  \
  VEOR y.B16, z.B16, x.B16;                      \
  VTBL INVERSE_SHIFT_ROWS.B16, [x.B16], x.B16;   \
  AESE ZERO.B16, x.B16;                          \	
  VAND x.B16, NIBBLE_MASK.B16, z.B16;            \
  VTBL z.B16, [M2L.B16], y.B16;                  \
  VUSHR $4, x.D2, x.D2;                          \
  VAND x.B16, NIBBLE_MASK.B16, z.B16;            \
  VTBL z.B16, [M2H.B16], z.B16;                  \
  VEOR y.B16, z.B16, x.B16

#define SM4_TAO_L1(x, y, z)         \
	SM4_SBOX(x, y, z);                                   \
	VTBL R08_MASK.B16, [x.B16], y.B16;                   \
	VEOR y.B16, x.B16, y.B16;                            \
	VTBL R16_MASK.B16, [x.B16], z.B16;                   \
	VEOR z.B16, y.B16, y.B16;                            \
	VSHL $2, y.S4, z.S4;                                 \
	VUSHR $30, y.S4, y.S4;                               \
	VORR y.B16, z.B16, y.B16;                            \
	VTBL R24_MASK.B16, [x.B16], z.B16;                   \
	VEOR z.B16, x.B16, x.B16;                            \
	VEOR y.B16, x.B16, x.B16
