// Generated by gen_sm3block_ni.go. DO NOT EDIT.
//go:build arm64 && !purego
// +build arm64,!purego

#include "textflag.h"

// func blockSM3NI(h []uint32, p []byte, t []uint32)
TEXT ·blockSM3NI(SB), 0, $0
	MOVD	h_base+0(FP), R0                           // Hash value first address
	MOVD	p_base+24(FP), R1                          // message first address
	MOVD	p_len+32(FP), R3                           // message length
	MOVD	t_base+48(FP), R2                          // t constants first address

	VLD1 (R0), [V8.S4, V9.S4]                          // load h(a,b,c,d,e,f,g,h)
	VREV64  V8.S4, V8.S4
	VEXT $8, V8.B16, V8.B16, V8.B16
	VREV64  V9.S4, V9.S4
	VEXT $8, V9.B16, V9.B16, V9.B16
	LDPW	(0*8)(R2), (R5, R6)                        // load t constants
    
blockloop:
	VLD1.P	64(R1), [V0.B16, V1.B16, V2.B16, V3.B16]    // load 64bytes message
	VMOV	V8.B16, V15.B16                             // backup: V8 h(dcba)
	VMOV	V9.B16, V16.B16                             // backup: V9 h(hgfe)
	VREV32	V0.B16, V0.B16                              // prepare for using message in Byte format
	VREV32	V1.B16, V1.B16
	VREV32	V2.B16, V2.B16
	VREV32	V3.B16, V3.B16    
	// first 16 rounds
	VMOV R5, V11.S[3]
	// Extension
	VEXT $12, V2.B16, V1.B16, V4.B16
	VEXT $12, V1.B16, V0.B16, V6.B16
	VEXT $8, V3.B16, V2.B16, V7.B16
	WORD $0xce63c004          //SM3PARTW1 V4.4S, V0.4S, V3.4S
	WORD $0xce66c4e4          //SM3PARTW2 V4.4S, V7.4S, V6.4S
	VEOR V1.B16, V0.B16, V10.B16
	// Compression
	WORD $0xce4b2505           //SM3SS1 V5.4S, V8.4S, V11.4S, V9.4S
	VSHL $1, V11.S4, V11.S4
	WORD $0xce4a80a8           //SM3TT1A V8d.4S, V5.4S, V10.S, 0
	WORD $0xce4088a9           //SM3TT2A V9d.4S, V5.4S, V0.S, 0
	WORD $0xce4b2505           //SM3SS1 V5.4S, V8.4S, V11.4S, V9.4S
	VSHL $1, V11.S4, V11.S4
	WORD $0xce4a90a8           //SM3TT1A V8d.4S, V5.4S, V10.S, 1
	WORD $0xce4098a9           //SM3TT2A V9d.4S, V5.4S, V0.S, 1
	WORD $0xce4b2505           //SM3SS1 V5.4S, V8.4S, V11.4S, V9.4S
	VSHL $1, V11.S4, V11.S4
	WORD $0xce4aa0a8           //SM3TT1A V8d.4S, V5.4S, V10.S, 2
	WORD $0xce40a8a9           //SM3TT2A V9d.4S, V5.4S, V0.S, 2
	WORD $0xce4b2505           //SM3SS1 V5.4S, V8.4S, V11.4S, V9.4S
	VSHL $1, V11.S4, V11.S4
	WORD $0xce4ab0a8           //SM3TT1A V8d.4S, V5.4S, V10.S, 3
	WORD $0xce40b8a9           //SM3TT2A V9d.4S, V5.4S, V0.S, 3

	// Extension
	VEXT $3, V3.B16, V2.B16, V0.B16
	VEXT $3, V2.B16, V1.B16, V6.B16
	VEXT $2, V4.B16, V3.B16, V7.B16
	WORD $0xce64c020          //SM3PARTW1 V0.4S, V1.4S, V4.4S
	WORD $0xce66c4e0          //SM3PARTW2 V0.4S, V7.4S, V6.4S
	VEOR V2.B16, V1.B16, V10.B16
	// Compression
	WORD $0xce4b2505           //SM3SS1 V5.4S, V8.4S, V11.4S, V9.4S
	VSHL $1, V11.S4, V11.S4
	WORD $0xce4a80a8           //SM3TT1A V8d.4S, V5.4S, V10.S, 0
	WORD $0xce4188a9           //SM3TT2A V9d.4S, V5.4S, V1.S, 0
	WORD $0xce4b2505           //SM3SS1 V5.4S, V8.4S, V11.4S, V9.4S
	VSHL $1, V11.S4, V11.S4
	WORD $0xce4a90a8           //SM3TT1A V8d.4S, V5.4S, V10.S, 1
	WORD $0xce4198a9           //SM3TT2A V9d.4S, V5.4S, V1.S, 1
	WORD $0xce4b2505           //SM3SS1 V5.4S, V8.4S, V11.4S, V9.4S
	VSHL $1, V11.S4, V11.S4
	WORD $0xce4aa0a8           //SM3TT1A V8d.4S, V5.4S, V10.S, 2
	WORD $0xce41a8a9           //SM3TT2A V9d.4S, V5.4S, V1.S, 2
	WORD $0xce4b2505           //SM3SS1 V5.4S, V8.4S, V11.4S, V9.4S
	VSHL $1, V11.S4, V11.S4
	WORD $0xce4ab0a8           //SM3TT1A V8d.4S, V5.4S, V10.S, 3
	WORD $0xce41b8a9           //SM3TT2A V9d.4S, V5.4S, V1.S, 3

	// Extension
	VEXT $12, V4.B16, V3.B16, V1.B16
	VEXT $12, V3.B16, V2.B16, V6.B16
	VEXT $8, V0.B16, V4.B16, V7.B16
	WORD $0xce60c041          //SM3PARTW1 V1.4S, V2.4S, V0.4S
	WORD $0xce66c4e1          //SM3PARTW2 V1.4S, V7.4S, V6.4S
	VEOR V3.B16, V2.B16, V10.B16
	// Compression
	WORD $0xce4b2505           //SM3SS1 V5.4S, V8.4S, V11.4S, V9.4S
	VSHL $1, V11.S4, V11.S4
	WORD $0xce4a80a8           //SM3TT1A V8d.4S, V5.4S, V10.S, 0
	WORD $0xce4288a9           //SM3TT2A V9d.4S, V5.4S, V2.S, 0
	WORD $0xce4b2505           //SM3SS1 V5.4S, V8.4S, V11.4S, V9.4S
	VSHL $1, V11.S4, V11.S4
	WORD $0xce4a90a8           //SM3TT1A V8d.4S, V5.4S, V10.S, 1
	WORD $0xce4298a9           //SM3TT2A V9d.4S, V5.4S, V2.S, 1
	WORD $0xce4b2505           //SM3SS1 V5.4S, V8.4S, V11.4S, V9.4S
	VSHL $1, V11.S4, V11.S4
	WORD $0xce4aa0a8           //SM3TT1A V8d.4S, V5.4S, V10.S, 2
	WORD $0xce42a8a9           //SM3TT2A V9d.4S, V5.4S, V2.S, 2
	WORD $0xce4b2505           //SM3SS1 V5.4S, V8.4S, V11.4S, V9.4S
	VSHL $1, V11.S4, V11.S4
	WORD $0xce4ab0a8           //SM3TT1A V8d.4S, V5.4S, V10.S, 3
	WORD $0xce42b8a9           //SM3TT2A V9d.4S, V5.4S, V2.S, 3

	// Extension
	VEXT $12, V0.B16, V4.B16, V2.B16
	VEXT $12, V4.B16, V3.B16, V6.B16
	VEXT $8, V1.B16, V0.B16, V7.B16
	WORD $0xce61c062          //SM3PARTW1 V2.4S, V3.4S, V1.4S
	WORD $0xce66c4e2          //SM3PARTW2 V2.4S, V7.4S, V6.4S
	VEOR V4.B16, V3.B16, V10.B16
	// Compression
	WORD $0xce4b2505           //SM3SS1 V5.4S, V8.4S, V11.4S, V9.4S
	VSHL $1, V11.S4, V11.S4
	WORD $0xce4a80a8           //SM3TT1A V8d.4S, V5.4S, V10.S, 0
	WORD $0xce4388a9           //SM3TT2A V9d.4S, V5.4S, V3.S, 0
	WORD $0xce4b2505           //SM3SS1 V5.4S, V8.4S, V11.4S, V9.4S
	VSHL $1, V11.S4, V11.S4
	WORD $0xce4a90a8           //SM3TT1A V8d.4S, V5.4S, V10.S, 1
	WORD $0xce4398a9           //SM3TT2A V9d.4S, V5.4S, V3.S, 1
	WORD $0xce4b2505           //SM3SS1 V5.4S, V8.4S, V11.4S, V9.4S
	VSHL $1, V11.S4, V11.S4
	WORD $0xce4aa0a8           //SM3TT1A V8d.4S, V5.4S, V10.S, 2
	WORD $0xce43a8a9           //SM3TT2A V9d.4S, V5.4S, V3.S, 2
	WORD $0xce4b2505           //SM3SS1 V5.4S, V8.4S, V11.4S, V9.4S
	VSHL $1, V11.S4, V11.S4
	WORD $0xce4ab0a8           //SM3TT1A V8d.4S, V5.4S, V10.S, 3
	WORD $0xce43b8a9           //SM3TT2A V9d.4S, V5.4S, V3.S, 3

	// second 48 rounds
	VMOV R6, V11.S[3]
	// Extension
	VEXT $12, V1.B16, V0.B16, V3.B16
	VEXT $12, V0.B16, V4.B16, V6.B16
	VEXT $8, V2.B16, V1.B16, V7.B16
	WORD $0xce62c083          //SM3PARTW1 V3.4S, V4.4S, V2.4S
	WORD $0xce66c4e3          //SM3PARTW2 V3.4S, V7.4S, V6.4S
	VEOR V0.B16, V4.B16, V10.B16
	// Compression
	WORD $0xce4b2505           //SM3SS1 V5.4S, V8.4S, V11.4S, V9.4S
	VSHL $1, V11.S4, V11.S4
	WORD $0xce4a84a8           //SM3TT1B V8d.4S, V5.4S, V10.S, 0
	WORD $0xce448ca9           //SM3TT2B V9d.4S, V5.4S, V4.S, 0
	WORD $0xce4b2505           //SM3SS1 V5.4S, V8.4S, V11.4S, V9.4S
	VSHL $1, V11.S4, V11.S4
	WORD $0xce4a94a8           //SM3TT1B V8d.4S, V5.4S, V10.S, 1
	WORD $0xce449ca9           //SM3TT2B V9d.4S, V5.4S, V4.S, 1
	WORD $0xce4b2505           //SM3SS1 V5.4S, V8.4S, V11.4S, V9.4S
	VSHL $1, V11.S4, V11.S4
	WORD $0xce4aa4a8           //SM3TT1B V8d.4S, V5.4S, V10.S, 2
	WORD $0xce44aca9           //SM3TT2B V9d.4S, V5.4S, V4.S, 2
	WORD $0xce4b2505           //SM3SS1 V5.4S, V8.4S, V11.4S, V9.4S
	VSHL $1, V11.S4, V11.S4
	WORD $0xce4ab4a8           //SM3TT1B V8d.4S, V5.4S, V10.S, 3
	WORD $0xce44bca9           //SM3TT2B V9d.4S, V5.4S, V4.S, 3

	// Extension
	VEXT $12, V2.B16, V1.B16, V4.B16
	VEXT $12, V1.B16, V0.B16, V6.B16
	VEXT $8, V3.B16, V2.B16, V7.B16
	WORD $0xce63c004          //SM3PARTW1 V4.4S, V0.4S, V3.4S
	WORD $0xce66c4e4          //SM3PARTW2 V4.4S, V7.4S, V6.4S
	VEOR V1.B16, V0.B16, V10.B16
	// Compression
	WORD $0xce4b2505           //SM3SS1 V5.4S, V8.4S, V11.4S, V9.4S
	VSHL $1, V11.S4, V11.S4
	WORD $0xce4a84a8           //SM3TT1B V8d.4S, V5.4S, V10.S, 0
	WORD $0xce408ca9           //SM3TT2B V9d.4S, V5.4S, V0.S, 0
	WORD $0xce4b2505           //SM3SS1 V5.4S, V8.4S, V11.4S, V9.4S
	VSHL $1, V11.S4, V11.S4
	WORD $0xce4a94a8           //SM3TT1B V8d.4S, V5.4S, V10.S, 1
	WORD $0xce409ca9           //SM3TT2B V9d.4S, V5.4S, V0.S, 1
	WORD $0xce4b2505           //SM3SS1 V5.4S, V8.4S, V11.4S, V9.4S
	VSHL $1, V11.S4, V11.S4
	WORD $0xce4aa4a8           //SM3TT1B V8d.4S, V5.4S, V10.S, 2
	WORD $0xce40aca9           //SM3TT2B V9d.4S, V5.4S, V0.S, 2
	WORD $0xce4b2505           //SM3SS1 V5.4S, V8.4S, V11.4S, V9.4S
	VSHL $1, V11.S4, V11.S4
	WORD $0xce4ab4a8           //SM3TT1B V8d.4S, V5.4S, V10.S, 3
	WORD $0xce40bca9           //SM3TT2B V9d.4S, V5.4S, V0.S, 3

	// Extension
	VEXT $12, V3.B16, V2.B16, V0.B16
	VEXT $12, V2.B16, V1.B16, V6.B16
	VEXT $8, V4.B16, V3.B16, V7.B16
	WORD $0xce64c020          //SM3PARTW1 V0.4S, V1.4S, V4.4S
	WORD $0xce66c4e0          //SM3PARTW2 V0.4S, V7.4S, V6.4S
	VEOR V2.B16, V1.B16, V10.B16
	// Compression
	WORD $0xce4b2505           //SM3SS1 V5.4S, V8.4S, V11.4S, V9.4S
	VSHL $1, V11.S4, V11.S4
	WORD $0xce4a84a8           //SM3TT1B V8d.4S, V5.4S, V10.S, 0
	WORD $0xce418ca9           //SM3TT2B V9d.4S, V5.4S, V1.S, 0
	WORD $0xce4b2505           //SM3SS1 V5.4S, V8.4S, V11.4S, V9.4S
	VSHL $1, V11.S4, V11.S4
	WORD $0xce4a94a8           //SM3TT1B V8d.4S, V5.4S, V10.S, 1
	WORD $0xce419ca9           //SM3TT2B V9d.4S, V5.4S, V1.S, 1
	WORD $0xce4b2505           //SM3SS1 V5.4S, V8.4S, V11.4S, V9.4S
	VSHL $1, V11.S4, V11.S4
	WORD $0xce4aa4a8           //SM3TT1B V8d.4S, V5.4S, V10.S, 2
	WORD $0xce41aca9           //SM3TT2B V9d.4S, V5.4S, V1.S, 2
	WORD $0xce4b2505           //SM3SS1 V5.4S, V8.4S, V11.4S, V9.4S
	VSHL $1, V11.S4, V11.S4
	WORD $0xce4ab4a8           //SM3TT1B V8d.4S, V5.4S, V10.S, 3
	WORD $0xce41bca9           //SM3TT2B V9d.4S, V5.4S, V1.S, 3

	// Extension
	VEXT $12, V4.B16, V3.B16, V1.B16
	VEXT $12, V3.B16, V2.B16, V6.B16
	VEXT $8, V0.B16, V4.B16, V7.B16
	WORD $0xce60c041          //SM3PARTW1 V1.4S, V2.4S, V0.4S
	WORD $0xce66c4e1          //SM3PARTW2 V1.4S, V7.4S, V6.4S
	VEOR V3.B16, V2.B16, V10.B16
	// Compression
	WORD $0xce4b2505           //SM3SS1 V5.4S, V8.4S, V11.4S, V9.4S
	VSHL $1, V11.S4, V11.S4
	WORD $0xce4a84a8           //SM3TT1B V8d.4S, V5.4S, V10.S, 0
	WORD $0xce428ca9           //SM3TT2B V9d.4S, V5.4S, V2.S, 0
	WORD $0xce4b2505           //SM3SS1 V5.4S, V8.4S, V11.4S, V9.4S
	VSHL $1, V11.S4, V11.S4
	WORD $0xce4a94a8           //SM3TT1B V8d.4S, V5.4S, V10.S, 1
	WORD $0xce429ca9           //SM3TT2B V9d.4S, V5.4S, V2.S, 1
	WORD $0xce4b2505           //SM3SS1 V5.4S, V8.4S, V11.4S, V9.4S
	VSHL $1, V11.S4, V11.S4
	WORD $0xce4aa4a8           //SM3TT1B V8d.4S, V5.4S, V10.S, 2
	WORD $0xce42aca9           //SM3TT2B V9d.4S, V5.4S, V2.S, 2
	WORD $0xce4b2505           //SM3SS1 V5.4S, V8.4S, V11.4S, V9.4S
	VSHL $1, V11.S4, V11.S4
	WORD $0xce4ab4a8           //SM3TT1B V8d.4S, V5.4S, V10.S, 3
	WORD $0xce42bca9           //SM3TT2B V9d.4S, V5.4S, V2.S, 3

	// Extension
	VEXT $12, V0.B16, V4.B16, V2.B16
	VEXT $12, V4.B16, V3.B16, V6.B16
	VEXT $8, V1.B16, V0.B16, V7.B16
	WORD $0xce61c062          //SM3PARTW1 V2.4S, V3.4S, V1.4S
	WORD $0xce66c4e2          //SM3PARTW2 V2.4S, V7.4S, V6.4S
	VEOR V4.B16, V3.B16, V10.B16
	// Compression
	WORD $0xce4b2505           //SM3SS1 V5.4S, V8.4S, V11.4S, V9.4S
	VSHL $1, V11.S4, V11.S4
	WORD $0xce4a84a8           //SM3TT1B V8d.4S, V5.4S, V10.S, 0
	WORD $0xce438ca9           //SM3TT2B V9d.4S, V5.4S, V3.S, 0
	WORD $0xce4b2505           //SM3SS1 V5.4S, V8.4S, V11.4S, V9.4S
	VSHL $1, V11.S4, V11.S4
	WORD $0xce4a94a8           //SM3TT1B V8d.4S, V5.4S, V10.S, 1
	WORD $0xce439ca9           //SM3TT2B V9d.4S, V5.4S, V3.S, 1
	WORD $0xce4b2505           //SM3SS1 V5.4S, V8.4S, V11.4S, V9.4S
	VSHL $1, V11.S4, V11.S4
	WORD $0xce4aa4a8           //SM3TT1B V8d.4S, V5.4S, V10.S, 2
	WORD $0xce43aca9           //SM3TT2B V9d.4S, V5.4S, V3.S, 2
	WORD $0xce4b2505           //SM3SS1 V5.4S, V8.4S, V11.4S, V9.4S
	VSHL $1, V11.S4, V11.S4
	WORD $0xce4ab4a8           //SM3TT1B V8d.4S, V5.4S, V10.S, 3
	WORD $0xce43bca9           //SM3TT2B V9d.4S, V5.4S, V3.S, 3

	// Extension
	VEXT $12, V1.B16, V0.B16, V3.B16
	VEXT $12, V0.B16, V4.B16, V6.B16
	VEXT $8, V2.B16, V1.B16, V7.B16
	WORD $0xce62c083          //SM3PARTW1 V3.4S, V4.4S, V2.4S
	WORD $0xce66c4e3          //SM3PARTW2 V3.4S, V7.4S, V6.4S
	VEOR V0.B16, V4.B16, V10.B16
	// Compression
	WORD $0xce4b2505           //SM3SS1 V5.4S, V8.4S, V11.4S, V9.4S
	VSHL $1, V11.S4, V11.S4
	WORD $0xce4a84a8           //SM3TT1B V8d.4S, V5.4S, V10.S, 0
	WORD $0xce448ca9           //SM3TT2B V9d.4S, V5.4S, V4.S, 0
	WORD $0xce4b2505           //SM3SS1 V5.4S, V8.4S, V11.4S, V9.4S
	VSHL $1, V11.S4, V11.S4
	WORD $0xce4a94a8           //SM3TT1B V8d.4S, V5.4S, V10.S, 1
	WORD $0xce449ca9           //SM3TT2B V9d.4S, V5.4S, V4.S, 1
	WORD $0xce4b2505           //SM3SS1 V5.4S, V8.4S, V11.4S, V9.4S
	VSHL $1, V11.S4, V11.S4
	WORD $0xce4aa4a8           //SM3TT1B V8d.4S, V5.4S, V10.S, 2
	WORD $0xce44aca9           //SM3TT2B V9d.4S, V5.4S, V4.S, 2
	WORD $0xce4b2505           //SM3SS1 V5.4S, V8.4S, V11.4S, V9.4S
	VSHL $1, V11.S4, V11.S4
	WORD $0xce4ab4a8           //SM3TT1B V8d.4S, V5.4S, V10.S, 3
	WORD $0xce44bca9           //SM3TT2B V9d.4S, V5.4S, V4.S, 3

	// Extension
	VEXT $12, V2.B16, V1.B16, V4.B16
	VEXT $12, V1.B16, V0.B16, V6.B16
	VEXT $8, V3.B16, V2.B16, V7.B16
	WORD $0xce63c004          //SM3PARTW1 V4.4S, V0.4S, V3.4S
	WORD $0xce66c4e4          //SM3PARTW2 V4.4S, V7.4S, V6.4S
	VEOR V1.B16, V0.B16, V10.B16
	// Compression
	WORD $0xce4b2505           //SM3SS1 V5.4S, V8.4S, V11.4S, V9.4S
	VSHL $1, V11.S4, V11.S4
	WORD $0xce4a84a8           //SM3TT1B V8d.4S, V5.4S, V10.S, 0
	WORD $0xce408ca9           //SM3TT2B V9d.4S, V5.4S, V0.S, 0
	WORD $0xce4b2505           //SM3SS1 V5.4S, V8.4S, V11.4S, V9.4S
	VSHL $1, V11.S4, V11.S4
	WORD $0xce4a94a8           //SM3TT1B V8d.4S, V5.4S, V10.S, 1
	WORD $0xce409ca9           //SM3TT2B V9d.4S, V5.4S, V0.S, 1
	WORD $0xce4b2505           //SM3SS1 V5.4S, V8.4S, V11.4S, V9.4S
	VSHL $1, V11.S4, V11.S4
	WORD $0xce4aa4a8           //SM3TT1B V8d.4S, V5.4S, V10.S, 2
	WORD $0xce40aca9           //SM3TT2B V9d.4S, V5.4S, V0.S, 2
	WORD $0xce4b2505           //SM3SS1 V5.4S, V8.4S, V11.4S, V9.4S
	VSHL $1, V11.S4, V11.S4
	WORD $0xce4ab4a8           //SM3TT1B V8d.4S, V5.4S, V10.S, 3
	WORD $0xce40bca9           //SM3TT2B V9d.4S, V5.4S, V0.S, 3

	// Extension
	VEXT $12, V3.B16, V2.B16, V0.B16
	VEXT $12, V2.B16, V1.B16, V6.B16
	VEXT $8, V4.B16, V3.B16, V7.B16
	WORD $0xce64c020          //SM3PARTW1 V0.4S, V1.4S, V4.4S
	WORD $0xce66c4e0          //SM3PARTW2 V0.4S, V7.4S, V6.4S
	VEOR V2.B16, V1.B16, V10.B16
	// Compression
	WORD $0xce4b2505           //SM3SS1 V5.4S, V8.4S, V11.4S, V9.4S
	VSHL $1, V11.S4, V11.S4
	WORD $0xce4a84a8           //SM3TT1B V8d.4S, V5.4S, V10.S, 0
	WORD $0xce418ca9           //SM3TT2B V9d.4S, V5.4S, V1.S, 0
	WORD $0xce4b2505           //SM3SS1 V5.4S, V8.4S, V11.4S, V9.4S
	VSHL $1, V11.S4, V11.S4
	WORD $0xce4a94a8           //SM3TT1B V8d.4S, V5.4S, V10.S, 1
	WORD $0xce419ca9           //SM3TT2B V9d.4S, V5.4S, V1.S, 1
	WORD $0xce4b2505           //SM3SS1 V5.4S, V8.4S, V11.4S, V9.4S
	VSHL $1, V11.S4, V11.S4
	WORD $0xce4aa4a8           //SM3TT1B V8d.4S, V5.4S, V10.S, 2
	WORD $0xce41aca9           //SM3TT2B V9d.4S, V5.4S, V1.S, 2
	WORD $0xce4b2505           //SM3SS1 V5.4S, V8.4S, V11.4S, V9.4S
	VSHL $1, V11.S4, V11.S4
	WORD $0xce4ab4a8           //SM3TT1B V8d.4S, V5.4S, V10.S, 3
	WORD $0xce41bca9           //SM3TT2B V9d.4S, V5.4S, V1.S, 3

	// Extension
	VEXT $12, V4.B16, V3.B16, V1.B16
	VEXT $12, V3.B16, V2.B16, V6.B16
	VEXT $8, V0.B16, V4.B16, V7.B16
	WORD $0xce60c041          //SM3PARTW1 V1.4S, V2.4S, V0.4S
	WORD $0xce66c4e1          //SM3PARTW2 V1.4S, V7.4S, V6.4S
	VEOR V3.B16, V2.B16, V10.B16
	// Compression
	WORD $0xce4b2505           //SM3SS1 V5.4S, V8.4S, V11.4S, V9.4S
	VSHL $1, V11.S4, V11.S4
	WORD $0xce4a84a8           //SM3TT1B V8d.4S, V5.4S, V10.S, 0
	WORD $0xce428ca9           //SM3TT2B V9d.4S, V5.4S, V2.S, 0
	WORD $0xce4b2505           //SM3SS1 V5.4S, V8.4S, V11.4S, V9.4S
	VSHL $1, V11.S4, V11.S4
	WORD $0xce4a94a8           //SM3TT1B V8d.4S, V5.4S, V10.S, 1
	WORD $0xce429ca9           //SM3TT2B V9d.4S, V5.4S, V2.S, 1
	WORD $0xce4b2505           //SM3SS1 V5.4S, V8.4S, V11.4S, V9.4S
	VSHL $1, V11.S4, V11.S4
	WORD $0xce4aa4a8           //SM3TT1B V8d.4S, V5.4S, V10.S, 2
	WORD $0xce42aca9           //SM3TT2B V9d.4S, V5.4S, V2.S, 2
	WORD $0xce4b2505           //SM3SS1 V5.4S, V8.4S, V11.4S, V9.4S
	VSHL $1, V11.S4, V11.S4
	WORD $0xce4ab4a8           //SM3TT1B V8d.4S, V5.4S, V10.S, 3
	WORD $0xce42bca9           //SM3TT2B V9d.4S, V5.4S, V2.S, 3

	VEOR V4.B16, V3.B16, V10.B16
	// Compression
	WORD $0xce4b2505           //SM3SS1 V5.4S, V8.4S, V11.4S, V9.4S
	VSHL $1, V11.S4, V11.S4
	WORD $0xce4a84a8           //SM3TT1B V8d.4S, V5.4S, V10.S, 0
	WORD $0xce438ca9           //SM3TT2B V9d.4S, V5.4S, V3.S, 0
	WORD $0xce4b2505           //SM3SS1 V5.4S, V8.4S, V11.4S, V9.4S
	VSHL $1, V11.S4, V11.S4
	WORD $0xce4a94a8           //SM3TT1B V8d.4S, V5.4S, V10.S, 1
	WORD $0xce439ca9           //SM3TT2B V9d.4S, V5.4S, V3.S, 1
	WORD $0xce4b2505           //SM3SS1 V5.4S, V8.4S, V11.4S, V9.4S
	VSHL $1, V11.S4, V11.S4
	WORD $0xce4aa4a8           //SM3TT1B V8d.4S, V5.4S, V10.S, 2
	WORD $0xce43aca9           //SM3TT2B V9d.4S, V5.4S, V3.S, 2
	WORD $0xce4b2505           //SM3SS1 V5.4S, V8.4S, V11.4S, V9.4S
	VSHL $1, V11.S4, V11.S4
	WORD $0xce4ab4a8           //SM3TT1B V8d.4S, V5.4S, V10.S, 3
	WORD $0xce43bca9           //SM3TT2B V9d.4S, V5.4S, V3.S, 3

	VEOR V0.B16, V4.B16, V10.B16
	// Compression
	WORD $0xce4b2505           //SM3SS1 V5.4S, V8.4S, V11.4S, V9.4S
	VSHL $1, V11.S4, V11.S4
	WORD $0xce4a84a8           //SM3TT1B V8d.4S, V5.4S, V10.S, 0
	WORD $0xce448ca9           //SM3TT2B V9d.4S, V5.4S, V4.S, 0
	WORD $0xce4b2505           //SM3SS1 V5.4S, V8.4S, V11.4S, V9.4S
	VSHL $1, V11.S4, V11.S4
	WORD $0xce4a94a8           //SM3TT1B V8d.4S, V5.4S, V10.S, 1
	WORD $0xce449ca9           //SM3TT2B V9d.4S, V5.4S, V4.S, 1
	WORD $0xce4b2505           //SM3SS1 V5.4S, V8.4S, V11.4S, V9.4S
	VSHL $1, V11.S4, V11.S4
	WORD $0xce4aa4a8           //SM3TT1B V8d.4S, V5.4S, V10.S, 2
	WORD $0xce44aca9           //SM3TT2B V9d.4S, V5.4S, V4.S, 2
	WORD $0xce4b2505           //SM3SS1 V5.4S, V8.4S, V11.4S, V9.4S
	VSHL $1, V11.S4, V11.S4
	WORD $0xce4ab4a8           //SM3TT1B V8d.4S, V5.4S, V10.S, 3
	WORD $0xce44bca9           //SM3TT2B V9d.4S, V5.4S, V4.S, 3

	VEOR V1.B16, V0.B16, V10.B16
	// Compression
	WORD $0xce4b2505           //SM3SS1 V5.4S, V8.4S, V11.4S, V9.4S
	VSHL $1, V11.S4, V11.S4
	WORD $0xce4a84a8           //SM3TT1B V8d.4S, V5.4S, V10.S, 0
	WORD $0xce408ca9           //SM3TT2B V9d.4S, V5.4S, V0.S, 0
	WORD $0xce4b2505           //SM3SS1 V5.4S, V8.4S, V11.4S, V9.4S
	VSHL $1, V11.S4, V11.S4
	WORD $0xce4a94a8           //SM3TT1B V8d.4S, V5.4S, V10.S, 1
	WORD $0xce409ca9           //SM3TT2B V9d.4S, V5.4S, V0.S, 1
	WORD $0xce4b2505           //SM3SS1 V5.4S, V8.4S, V11.4S, V9.4S
	VSHL $1, V11.S4, V11.S4
	WORD $0xce4aa4a8           //SM3TT1B V8d.4S, V5.4S, V10.S, 2
	WORD $0xce40aca9           //SM3TT2B V9d.4S, V5.4S, V0.S, 2
	WORD $0xce4b2505           //SM3SS1 V5.4S, V8.4S, V11.4S, V9.4S
	VSHL $1, V11.S4, V11.S4
	WORD $0xce4ab4a8           //SM3TT1B V8d.4S, V5.4S, V10.S, 3
	WORD $0xce40bca9           //SM3TT2B V9d.4S, V5.4S, V0.S, 3

	SUB	$64, R3, R3                                  // message length - 64bytes, then compare with 64bytes
	VEOR	V8.B16, V15.B16, V8.B16
	VEOR	V9.B16, V16.B16, V9.B16
	CBNZ	R3, blockloop

sm3ret:
	VREV64  V8.S4, V8.S4
	VEXT $8, V8.B16, V8.B16, V8.B16
	VREV64  V9.S4, V9.S4
	VEXT $8, V9.B16, V9.B16, V9.B16
	VST1	[V8.S4, V9.S4], (R0)                       // store hash value H	
	RET
