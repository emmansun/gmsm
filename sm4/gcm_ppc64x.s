// Copyright 2019 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build (ppc64 || ppc64le) && !purego

// Portions based on CRYPTOGAMS code with the following comment:
// # ====================================================================
// # Written by Andy Polyakov <appro@openssl.org> for the OpenSSL
// # project. The module is, however, dual licensed under OpenSSL and
// # CRYPTOGAMS licenses depending on where you obtain it. For further
// # details see http://www.openssl.org/~appro/cryptogams/.
// # ====================================================================

// The implementations for gcmHash, gcmInit and gcmMul are based on the generated asm
// from the script https://github.com/dot-asm/cryptogams/blob/master/ppc/ghashp8-ppc.pl
// from commit d47afb3c.

// Changes were made due to differences in the ABI and some register usage.
// Some arguments were changed due to the way the Go code passes them.

#include "textflag.h"

#define XIP    R3
#define HTBL   R4
#define INP    R5
#define LEN    R6

#define XL     V0
#define XM     V1
#define XH     V2
#define IN     V3
#define ZERO   V4
#define T0     V5
#define T1     V6
#define T2     V7
#define XC2    V8
#define H      V9
#define HH     V10
#define HL     V11
#define LEMASK V12
#define XL1    V13
#define XM1    V14
#define XH1    V15
#define IN1    V16
#define H2     V17
#define H2H    V18
#define H2L    V19
#define XL3    V20
#define XM2    V21
#define IN2    V22
#define H3L    V23
#define H3     V24
#define H3H    V25
#define XH3    V26
#define XM3    V27
#define IN3    V28
#define H4L    V29
#define H4     V30
#define H4H    V31

#define IN0    IN
#define H21L   HL
#define H21H   HH
#define LOPERM H2L
#define HIPERM H2H

#define VXL    VS32
#define VIN    VS35
#define VXC2   VS40
#define VH     VS41
#define VHH    VS42
#define VHL    VS43
#define VIN1   VS48
#define VH2    VS49
#define VH2H   VS50
#define VH2L   VS51

#define VIN2   VS54
#define VH3L   VS55
#define VH3    VS56
#define VH3H   VS57
#define VIN3   VS60
#define VH4L   VS61
#define VH4    VS62
#define VH4H   VS63

#define VIN0   VIN

// func gcmInit(productTable *[256]byte, h []byte)
TEXT ·gcmInit(SB), NOSPLIT, $0-32
	MOVD productTable+0(FP), XIP
	MOVD h+8(FP), HTBL

	MOVD   $0x10, R8
	MOVD   $0x20, R9
	MOVD   $0x30, R10
	LXVD2X (HTBL)(R0), VH // Load H

	VSPLTISB $-16, XC2           // 0xf0
	VSPLTISB $1, T0              // one
	VADDUBM  XC2, XC2, XC2       // 0xe0
	VXOR     ZERO, ZERO, ZERO
	VOR      XC2, T0, XC2        // 0xe1
	VSLDOI   $15, XC2, ZERO, XC2 // 0xe1...
	VSLDOI   $1, ZERO, T0, T1    // ...1
	VADDUBM  XC2, XC2, XC2       // 0xc2...
	VSPLTISB $7, T2
	VOR      XC2, T1, XC2        // 0xc2....01
	VSPLTB   $0, H, T1           // most significant byte
	VSL      H, T0, H            // H<<=1
	VSRAB    T1, T2, T1          // broadcast carry bit
	VAND     T1, XC2, T1
	VXOR     H, T1, IN           // twisted H

	VSLDOI $8, IN, IN, H      // twist even more ...
	VSLDOI $8, ZERO, XC2, XC2 // 0xc2.0
	VSLDOI $8, ZERO, H, HL    // ... and split
	VSLDOI $8, H, ZERO, HH

	STXVD2X VXC2, (XIP+R0) // save pre-computed table
	STXVD2X VHL, (XIP+R8)
	MOVD    $0x40, R8
	STXVD2X VH, (XIP+R9)
	MOVD    $0x50, R9
	STXVD2X VHH, (XIP+R10)
	MOVD    $0x60, R10

	VPMSUMD IN, HL, XL // H.lo·H.lo
	VPMSUMD IN, H, XM  // H.hi·H.lo+H.lo·H.hi
	VPMSUMD IN, HH, XH // H.hi·H.hi

	VPMSUMD XL, XC2, T2 // 1st reduction phase

	VSLDOI $8, XM, ZERO, T0
	VSLDOI $8, ZERO, XM, T1
	VXOR   XL, T0, XL
	VXOR   XH, T1, XH

	VSLDOI $8, XL, XL, XL
	VXOR   XL, T2, XL

	VSLDOI  $8, XL, XL, T1 // 2nd reduction phase
	VPMSUMD XL, XC2, XL
	VXOR    T1, XH, T1
	VXOR    XL, T1, IN1

	VSLDOI $8, IN1, IN1, H2
	VSLDOI $8, ZERO, H2, H2L
	VSLDOI $8, H2, ZERO, H2H

	STXVD2X VH2L, (XIP+R8)  // save H^2
	MOVD    $0x70, R8
	STXVD2X VH2, (XIP+R9)
	MOVD    $0x80, R9
	STXVD2X VH2H, (XIP+R10)
	MOVD    $0x90, R10

	VPMSUMD IN, H2L, XL   // H.lo·H^2.lo
	VPMSUMD IN1, H2L, XL1 // H^2.lo·H^2.lo
	VPMSUMD IN, H2, XM    // H.hi·H^2.lo+H.lo·H^2.hi
	VPMSUMD IN1, H2, XM1  // H^2.hi·H^2.lo+H^2.lo·H^2.hi
	VPMSUMD IN, H2H, XH   // H.hi·H^2.hi
	VPMSUMD IN1, H2H, XH1 // H^2.hi·H^2.hi

	VPMSUMD XL, XC2, T2  // 1st reduction phase
	VPMSUMD XL1, XC2, HH // 1st reduction phase

	VSLDOI $8, XM, ZERO, T0
	VSLDOI $8, ZERO, XM, T1
	VSLDOI $8, XM1, ZERO, HL
	VSLDOI $8, ZERO, XM1, H
	VXOR   XL, T0, XL
	VXOR   XH, T1, XH
	VXOR   XL1, HL, XL1
	VXOR   XH1, H, XH1

	VSLDOI $8, XL, XL, XL
	VSLDOI $8, XL1, XL1, XL1
	VXOR   XL, T2, XL
	VXOR   XL1, HH, XL1

	VSLDOI  $8, XL, XL, T1  // 2nd reduction phase
	VSLDOI  $8, XL1, XL1, H // 2nd reduction phase
	VPMSUMD XL, XC2, XL
	VPMSUMD XL1, XC2, XL1
	VXOR    T1, XH, T1
	VXOR    H, XH1, H
	VXOR    XL, T1, XL
	VXOR    XL1, H, XL1

	VSLDOI $8, XL, XL, H
	VSLDOI $8, XL1, XL1, H2
	VSLDOI $8, ZERO, H, HL
	VSLDOI $8, H, ZERO, HH
	VSLDOI $8, ZERO, H2, H2L
	VSLDOI $8, H2, ZERO, H2H

	STXVD2X VHL, (XIP+R8)   // save H^3
	MOVD    $0xa0, R8
	STXVD2X VH, (XIP+R9)
	MOVD    $0xb0, R9
	STXVD2X VHH, (XIP+R10)
	MOVD    $0xc0, R10
	STXVD2X VH2L, (XIP+R8)  // save H^4
	STXVD2X VH2, (XIP+R9)
	STXVD2X VH2H, (XIP+R10)

	RET

// func gcmHash(output []byte, productTable *[256]byte, inp []byte, len int)
TEXT ·gcmHash(SB), NOSPLIT, $0-64
	MOVD output+0(FP), XIP
	MOVD productTable+24(FP), HTBL
	MOVD inp+32(FP), INP
	MOVD len+56(FP), LEN

	MOVD   $0x10, R8
	MOVD   $0x20, R9
	MOVD   $0x30, R10
	LXVD2X (XIP)(R0), VXL // load Xi

	LXVD2X   (HTBL)(R8), VHL    // load pre-computed table
	MOVD     $0x40, R8
	LXVD2X   (HTBL)(R9), VH
	MOVD     $0x50, R9
	LXVD2X   (HTBL)(R10), VHH
	MOVD     $0x60, R10
	LXVD2X   (HTBL)(R0), VXC2
#ifdef GOARCH_ppc64le
	LVSL     (R0)(R0), LEMASK
	VSPLTISB $0x07, T0
	VXOR     LEMASK, T0, LEMASK
	VPERM    XL, XL, LEMASK, XL
#endif
	VXOR     ZERO, ZERO, ZERO

	CMPU LEN, $64
	BGE  gcm_ghash_p8_4x

	LXVD2X (INP)(R0), VIN
	ADD    $16, INP, INP
	SUBCCC $16, LEN, LEN
#ifdef GOARCH_ppc64le
	VPERM  IN, IN, LEMASK, IN
#endif
	VXOR   IN, XL, IN
	BEQ    short

	LXVD2X (HTBL)(R8), VH2L  // load H^2
	MOVD   $16, R8
	LXVD2X (HTBL)(R9), VH2
	ADD    LEN, INP, R9      // end of input
	LXVD2X (HTBL)(R10), VH2H

loop_2x:
	LXVD2X (INP)(R0), VIN1
#ifdef GOARCH_ppc64le
	VPERM  IN1, IN1, LEMASK, IN1
#endif

	SUBC    $32, LEN, LEN
	VPMSUMD IN, H2L, XL   // H^2.lo·Xi.lo
	VPMSUMD IN1, HL, XL1  // H.lo·Xi+1.lo
	SUBE    R11, R11, R11 // borrow?-1:0
	VPMSUMD IN, H2, XM    // H^2.hi·Xi.lo+H^2.lo·Xi.hi
	VPMSUMD IN1, H, XM1   // H.hi·Xi+1.lo+H.lo·Xi+1.hi
	AND     LEN, R11, R11
	VPMSUMD IN, H2H, XH   // H^2.hi·Xi.hi
	VPMSUMD IN1, HH, XH1  // H.hi·Xi+1.hi
	ADD     R11, INP, INP

	VXOR XL, XL1, XL
	VXOR XM, XM1, XM

	VPMSUMD XL, XC2, T2 // 1st reduction phase

	VSLDOI $8, XM, ZERO, T0
	VSLDOI $8, ZERO, XM, T1
	VXOR   XH, XH1, XH
	VXOR   XL, T0, XL
	VXOR   XH, T1, XH

	VSLDOI $8, XL, XL, XL
	VXOR   XL, T2, XL
	LXVD2X (INP)(R8), VIN
	ADD    $32, INP, INP

	VSLDOI  $8, XL, XL, T1     // 2nd reduction phase
	VPMSUMD XL, XC2, XL
#ifdef GOARCH_ppc64le
	VPERM   IN, IN, LEMASK, IN
#endif
	VXOR    T1, XH, T1
	VXOR    IN, T1, IN
	VXOR    IN, XL, IN
	CMP     R9, INP
	BGT     loop_2x            // done yet?

	CMPWU LEN, $0
	BNE   even

short:
	VPMSUMD IN, HL, XL // H.lo·Xi.lo
	VPMSUMD IN, H, XM  // H.hi·Xi.lo+H.lo·Xi.hi
	VPMSUMD IN, HH, XH // H.hi·Xi.hi

	VPMSUMD XL, XC2, T2 // 1st reduction phase

	VSLDOI $8, XM, ZERO, T0
	VSLDOI $8, ZERO, XM, T1
	VXOR   XL, T0, XL
	VXOR   XH, T1, XH

	VSLDOI $8, XL, XL, XL
	VXOR   XL, T2, XL

	VSLDOI  $8, XL, XL, T1 // 2nd reduction phase
	VPMSUMD XL, XC2, XL
	VXOR    T1, XH, T1

even:
	VXOR    XL, T1, XL
#ifdef GOARCH_ppc64le
	VPERM   XL, XL, LEMASK, XL
#endif
	STXVD2X VXL, (XIP+R0)

	OR R12, R12, R12 // write out Xi
	RET

gcm_ghash_p8_4x:
	LVSL     (R8)(R0), T0      // 0x0001..0e0f
	MOVD     $0x70, R8
	LXVD2X   (HTBL)(R9), VH2
	MOVD     $0x80, R9
	VSPLTISB $8, T1            // 0x0808..0808
	MOVD     $0x90, R10
	LXVD2X   (HTBL)(R8), VH3L  // load H^3
	MOVD     $0xa0, R8
	LXVD2X   (HTBL)(R9), VH3
	MOVD     $0xb0, R9
	LXVD2X   (HTBL)(R10), VH3H
	MOVD     $0xc0, R10
	LXVD2X   (HTBL)(R8), VH4L  // load H^4
	MOVD     $0x10, R8
	LXVD2X   (HTBL)(R9), VH4
	MOVD     $0x20, R9
	LXVD2X   (HTBL)(R10), VH4H
	MOVD     $0x30, R10

	VSLDOI  $8, ZERO, T1, T2   // 0x0000..0808
	VADDUBM T0, T2, HIPERM     // 0x0001..1617
	VADDUBM T1, HIPERM, LOPERM // 0x0809..1e1f

	SRD $4, LEN, LEN // this allows to use sign bit as carry

	LXVD2X (INP)(R0), VIN0       // load input
	LXVD2X (INP)(R8), VIN1
	SUBCCC $8, LEN, LEN
	LXVD2X (INP)(R9), VIN2
	LXVD2X (INP)(R10), VIN3
	ADD    $0x40, INP, INP
#ifdef GOARCH_ppc64le
	VPERM  IN0, IN0, LEMASK, IN0
	VPERM  IN1, IN1, LEMASK, IN1
	VPERM  IN2, IN2, LEMASK, IN2
	VPERM  IN3, IN3, LEMASK, IN3
#endif

	VXOR IN0, XL, XH

	VPMSUMD IN1, H3L, XL1
	VPMSUMD IN1, H3, XM1
	VPMSUMD IN1, H3H, XH1

	VPERM   H2, H, HIPERM, H21L
	VPERM   IN2, IN3, LOPERM, T0
	VPERM   H2, H, LOPERM, H21H
	VPERM   IN2, IN3, HIPERM, T1
	VPMSUMD IN2, H2, XM2         // H^2.lo·Xi+2.hi+H^2.hi·Xi+2.lo
	VPMSUMD T0, H21L, XL3        // H^2.lo·Xi+2.lo+H.lo·Xi+3.lo
	VPMSUMD IN3, H, XM3          // H.hi·Xi+3.lo  +H.lo·Xi+3.hi
	VPMSUMD T1, H21H, XH3        // H^2.hi·Xi+2.hi+H.hi·Xi+3.hi

	VXOR XM2, XM1, XM2
	VXOR XL3, XL1, XL3
	VXOR XM3, XM2, XM3
	VXOR XH3, XH1, XH3

	BLT tail_4x

loop_4x:
	LXVD2X (INP)(R0), VIN0
	LXVD2X (INP)(R8), VIN1
	SUBCCC $4, LEN, LEN
	LXVD2X (INP)(R9), VIN2
	LXVD2X (INP)(R10), VIN3
	ADD    $0x40, INP, INP
#ifdef GOARCH_ppc64le
	VPERM  IN1, IN1, LEMASK, IN1
	VPERM  IN2, IN2, LEMASK, IN2
	VPERM  IN3, IN3, LEMASK, IN3
	VPERM  IN0, IN0, LEMASK, IN0
#endif

	VPMSUMD XH, H4L, XL   // H^4.lo·Xi.lo
	VPMSUMD XH, H4, XM    // H^4.hi·Xi.lo+H^4.lo·Xi.hi
	VPMSUMD XH, H4H, XH   // H^4.hi·Xi.hi
	VPMSUMD IN1, H3L, XL1
	VPMSUMD IN1, H3, XM1
	VPMSUMD IN1, H3H, XH1

	VXOR  XL, XL3, XL
	VXOR  XM, XM3, XM
	VXOR  XH, XH3, XH
	VPERM IN2, IN3, LOPERM, T0
	VPERM IN2, IN3, HIPERM, T1

	VPMSUMD XL, XC2, T2   // 1st reduction phase
	VPMSUMD T0, H21L, XL3 // H.lo·Xi+3.lo  +H^2.lo·Xi+2.lo
	VPMSUMD T1, H21H, XH3 // H.hi·Xi+3.hi  +H^2.hi·Xi+2.hi

	VSLDOI $8, XM, ZERO, T0
	VSLDOI $8, ZERO, XM, T1
	VXOR   XL, T0, XL
	VXOR   XH, T1, XH

	VSLDOI $8, XL, XL, XL
	VXOR   XL, T2, XL

	VSLDOI  $8, XL, XL, T1 // 2nd reduction phase
	VPMSUMD IN2, H2, XM2   // H^2.hi·Xi+2.lo+H^2.lo·Xi+2.hi
	VPMSUMD IN3, H, XM3    // H.hi·Xi+3.lo  +H.lo·Xi+3.hi
	VPMSUMD XL, XC2, XL

	VXOR XL3, XL1, XL3
	VXOR XH3, XH1, XH3
	VXOR XH, IN0, XH
	VXOR XM2, XM1, XM2
	VXOR XH, T1, XH
	VXOR XM3, XM2, XM3
	VXOR XH, XL, XH
	BGE  loop_4x

tail_4x:
	VPMSUMD XH, H4L, XL // H^4.lo·Xi.lo
	VPMSUMD XH, H4, XM  // H^4.hi·Xi.lo+H^4.lo·Xi.hi
	VPMSUMD XH, H4H, XH // H^4.hi·Xi.hi

	VXOR XL, XL3, XL
	VXOR XM, XM3, XM

	VPMSUMD XL, XC2, T2 // 1st reduction phase

	VSLDOI $8, XM, ZERO, T0
	VSLDOI $8, ZERO, XM, T1
	VXOR   XH, XH3, XH
	VXOR   XL, T0, XL
	VXOR   XH, T1, XH

	VSLDOI $8, XL, XL, XL
	VXOR   XL, T2, XL

	VSLDOI  $8, XL, XL, T1 // 2nd reduction phase
	VPMSUMD XL, XC2, XL
	VXOR    T1, XH, T1
	VXOR    XL, T1, XL

	ADDCCC $4, LEN, LEN
	BEQ    done_4x

	LXVD2X (INP)(R0), VIN0
	CMPU   LEN, $2
	MOVD   $-4, LEN
	BLT    one
	LXVD2X (INP)(R8), VIN1
	BEQ    two

three:
	LXVD2X (INP)(R9), VIN2
#ifdef GOARCH_ppc64le
	VPERM  IN0, IN0, LEMASK, IN0
	VPERM  IN1, IN1, LEMASK, IN1
	VPERM  IN2, IN2, LEMASK, IN2
#endif

	VXOR IN0, XL, XH
	VOR  H3L, H3L, H4L
	VOR  H3, H3, H4
	VOR  H3H, H3H, H4H

	VPERM   IN1, IN2, LOPERM, T0
	VPERM   IN1, IN2, HIPERM, T1
	VPMSUMD IN1, H2, XM2         // H^2.lo·Xi+1.hi+H^2.hi·Xi+1.lo
	VPMSUMD IN2, H, XM3          // H.hi·Xi+2.lo  +H.lo·Xi+2.hi
	VPMSUMD T0, H21L, XL3        // H^2.lo·Xi+1.lo+H.lo·Xi+2.lo
	VPMSUMD T1, H21H, XH3        // H^2.hi·Xi+1.hi+H.hi·Xi+2.hi

	VXOR XM3, XM2, XM3
	JMP  tail_4x

two:
#ifdef GOARCH_ppc64le
	VPERM IN0, IN0, LEMASK, IN0
	VPERM IN1, IN1, LEMASK, IN1
#endif

	VXOR  IN, XL, XH
	VPERM ZERO, IN1, LOPERM, T0
	VPERM ZERO, IN1, HIPERM, T1

	VSLDOI $8, ZERO, H2, H4L
	VOR    H2, H2, H4
	VSLDOI $8, H2, ZERO, H4H

	VPMSUMD T0, H21L, XL3 // H.lo·Xi+1.lo
	VPMSUMD IN1, H, XM3   // H.hi·Xi+1.lo+H.lo·Xi+2.hi
	VPMSUMD T1, H21H, XH3 // H.hi·Xi+1.hi

	JMP tail_4x

one:
#ifdef GOARCH_ppc64le
	VPERM IN0, IN0, LEMASK, IN0
#endif

	VSLDOI $8, ZERO, H, H4L
	VOR    H, H, H4
	VSLDOI $8, H, ZERO, H4H

	VXOR IN0, XL, XH
	VXOR XL3, XL3, XL3
	VXOR XM3, XM3, XM3
	VXOR XH3, XH3, XH3

	JMP tail_4x

done_4x:
#ifdef GOARCH_ppc64le
	VPERM   XL, XL, LEMASK, XL
#endif
	STXVD2X VXL, (XIP+R0)      // write out Xi
	RET

// func gcmMul(output []byte, productTable *[256]byte)
TEXT ·gcmMul(SB), NOSPLIT, $0-32
	MOVD output+0(FP), XIP
	MOVD productTable+24(FP), HTBL

	MOVD   $0x10, R8
	MOVD   $0x20, R9
	MOVD   $0x30, R10
	LXVD2X (XIP)(R0), VIN // load Xi

	LXVD2X   (HTBL)(R8), VHL    // Load pre-computed table
	LXVD2X   (HTBL)(R9), VH
	LXVD2X   (HTBL)(R10), VHH
	LXVD2X   (HTBL)(R0), VXC2
#ifdef GOARCH_ppc64le
	VSPLTISB $0x07, T0
	VXOR     LEMASK, T0, LEMASK
	VPERM    IN, IN, LEMASK, IN
#endif
	VXOR     ZERO, ZERO, ZERO

	VPMSUMD IN, HL, XL // H.lo·Xi.lo
	VPMSUMD IN, H, XM  // H.hi·Xi.lo+H.lo·Xi.hi
	VPMSUMD IN, HH, XH // H.hi·Xi.hi

	VPMSUMD XL, XC2, T2 // 1st reduction phase

	VSLDOI $8, XM, ZERO, T0
	VSLDOI $8, ZERO, XM, T1
	VXOR   XL, T0, XL
	VXOR   XH, T1, XH

	VSLDOI $8, XL, XL, XL
	VXOR   XL, T2, XL

	VSLDOI  $8, XL, XL, T1 // 2nd reduction phase
	VPMSUMD XL, XC2, XL
	VXOR    T1, XH, T1
	VXOR    XL, T1, XL

#ifdef GOARCH_ppc64le
	VPERM   XL, XL, LEMASK, XL
#endif
	STXVD2X VXL, (XIP+R0)      // write out Xi
	RET
