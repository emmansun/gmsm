// --- VEX and ModRM Helper Macros ---
// R' bit (Bit 7 of VEX.Byte2): Extends ModRM.reg. Inverted: 1 means no extension (0-7), 0 means extension (+8).
#define VEX_Rp(x)  (1 - ((x) >> 3))
// B' bit (Bit 5 of VEX.Byte2): Extends ModRM.rm or SIB.base. Inverted logic same as R'.
#define VEX_Bp(x)  (1 - ((x) >> 3))
// vvvv field (Bits 6:3 of VEX.Byte3): Encodes the first source operand (Xs1). Fully inverted (4 bits).
#define VEX_VVVV(x) (15 - (x))
// ModRM.reg field (Bits 5:3 of ModRM): Encodes the destination operand (Xd).
#define MODRM_REG3(x) (((x) & 7) << 3)
// ModRM.rm field (Bits 2:0 of ModRM): Encodes the second source operand (Xs2) or base register.
#define MODRM_RM3(x)  ((x) & 7)

// --- Instruction Macros (Intel Syntax: Xd, Xs1, Xs2) ---
// VSM4KEY4 xmm1, xmm2, xmm3
// Opcode Map: VEX.NDS.LIG.66.0F38.W0 DA /r
// Mapping: Xd -> reg, Xs1 -> vvvv, Xs2 -> rm
#define VSM4KEY4(Xd, Xs1, Xs2) \
	BYTE $0xC4; \
	/* VEX.Byte2: [R'(Xd) X'=1 B'(Xs2) m=00010(0F38)] -> Base 0x62 */ \
	BYTE $((0x62) | (VEX_Bp(Xs2) << 5) | (VEX_Rp(Xd) << 7)); \
	/* VEX.Byte3: [W=0 vvvv(Xs1) L=1 pp=10(66h)] -> Base 0x02 */ \
	BYTE $((0x02) | (VEX_VVVV(Xs1) << 3)); \
	BYTE $0xDA; \
	/* ModRM: [mod=11 reg(Xd) rm(Xs2)] -> Base 0xC0 */ \
	BYTE $((0xC0) | MODRM_RM3(Xs2) | MODRM_REG3(Xd))

// VSM4RNDS4 xmm1, xmm2, xmm3
// Opcode Map: VEX.NDS.LIG.F2.0F38.W0 DA /r
// Mapping: Xd -> reg, Xs1 -> vvvv, Xs2 -> rm
#define VSM4RNDS4(Xd, Xs1, Xs2) \
	BYTE $0xC4; \
	/* VEX.Byte2: [R'(Xd) X'=1 B'(Xs2) m=00010(0F38)] -> Base 0x62 */ \
	BYTE $((0x62) | (VEX_Bp(Xs2) << 5) | (VEX_Rp(Xd) << 7)); \
	/* VEX.Byte3: [W=0 vvvv(Xs1) L=1 pp=11(F2h)] -> Base 0x03 */ \
	BYTE $((0x03) | (VEX_VVVV(Xs1) << 3)); \
	BYTE $0xDA; \
	/* ModRM: [mod=11 reg(Xd) rm(Xs2)] -> Base 0xC0 */ \
	BYTE $((0xC0) | MODRM_RM3(Xs2) | MODRM_REG3(Xd))


// --- Memory Variants (Base register RAX) ---
// Note: Renamed parameters to (Xd, Xs1) to match the semantic role of the register variants.
// RAX is register 0, so B'=1 (no extension) and rm=000.

// VSM4RNDS4 Xd, Xs1, (%rax) 
// mod = 00 (memory, no displacement), rm = 000 (RAX), B' = 1 (no extension)
#define VSM4RNDS4_MEM_NO_OFF_RAX(Xd, Xs1) \
    BYTE $0xC4; \
    /* VEX.Byte2: [R'(Xd) X'=1 B'=1(rax) m=00010] -> Base 0x62 */ \
    BYTE $((0x62) | (VEX_Rp(Xd) << 7)); \
    /* VEX.Byte3: [W=0 vvvv(Xs1) L=1 pp=11(F2h)] -> Base 0x03 */ \
    BYTE $((0x03) | (VEX_VVVV(Xs1) << 3)); \
    BYTE $0xDA; \
    /* ModRM: [mod=00 reg(Xd) rm=000(rax)] -> Base 0x00 */ \
    BYTE $((0x00) | MODRM_REG3(Xd))

// VSM4RNDS4 Xd, Xs1, offset(%rax)   (8-bit displacement)
// mod = 01 (memory + disp8), rm = 000 (RAX), B' = 1 (no extension)
#define VSM4RNDS4_MEM_8BIT_OFF_RAX(Xd, Xs1, OFFSET) \
    BYTE $0xC4; \
    /* VEX.Byte2: [R'(Xd) X'=1 B'=1(rax) m=00010] -> Base 0x62 */ \
    BYTE $((0x62) | (VEX_Rp(Xd) << 7)); \
    /* VEX.Byte3: [W=0 vvvv(Xs1) L=1 pp=11(F2h)] -> Base 0x03 */ \
    BYTE $((0x03) | (VEX_VVVV(Xs1) << 3)); \
    BYTE $0xDA; \
    /* ModRM: [mod=01 reg(Xd) rm=000(rax)] -> Base 0x40 */ \
    BYTE $((0x40) | MODRM_REG3(Xd)); \
    /* Displacement */ \
    BYTE $((OFFSET) & 0xFF)

#define VSM4RNDS32_MEM_RAX(Xd) \
	VSM4RNDS4_MEM_NO_OFF_RAX(Xd, Xd); \
	VSM4RNDS4_MEM_8BIT_OFF_RAX(Xd, Xd, 16); \
	VSM4RNDS4_MEM_8BIT_OFF_RAX(Xd, Xd, 32); \
	VSM4RNDS4_MEM_8BIT_OFF_RAX(Xd, Xd, 48); \
	VSM4RNDS4_MEM_8BIT_OFF_RAX(Xd, Xd, 64); \
	VSM4RNDS4_MEM_8BIT_OFF_RAX(Xd, Xd, 80); \
	VSM4RNDS4_MEM_8BIT_OFF_RAX(Xd, Xd, 96); \
	VSM4RNDS4_MEM_8BIT_OFF_RAX(Xd, Xd, 112)
