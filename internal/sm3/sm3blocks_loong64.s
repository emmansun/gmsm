// Copyright 2025 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build !purego

#include "textflag.h"

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
#define TRANSPOSE_MATRIX(t0, t1, t2, t3, RTMP0, RTMP1, RTMP2, RTMP3) \
    VILVLW t1, t0, RTMP0; /* RTMP0 = {t1.S2, t0.S2, t1.S0, t0.S0} */ \
    VILVLW t3, t2, RTMP1; /* RTMP0 = {t3.S2, t2.S2, t3.S0, t2.S0} */ \
    VILVHW t1, t0, RTMP2; /* RTMP2 = {t1.S3, t0.S3, t1.S1, t0.S1} */ \
    VILVHW t3, t2, RTMP3; /* RTMP3 = {t3.S3, t2.S3, t3.S1, t2.S1} */ \
    VILVLD RTMP1, RTMP0, t0; /* t0 = {t3.S0, t2.S0, t1.S0, t0.S0} */ \
    VILVLD RTMP3, RTMP2, t1; /* t1 = {t3.S1, t2.S1, t1.S1, t0.S1} */ \
    VILVHD RTMP1, RTMP0, t2; /* t2 = {t3.S2, t2.S2, t1.S2, t0.S2} */ \
    VILVHD RTMP3, RTMP2, t3; /* t3 = {t3.S3, t2.S3, t1.S3, t0.S3} */


// transposeMatrix8x8(dig **[8]uint32)
TEXT ·transposeMatrix8x8(SB),NOSPLIT,$0
#define digPtr R4
    MOVV	dig+0(FP), digPtr
    MOVV (0*8)(digPtr), R20
    VMOVQ (0*16)(R20), V0
    VMOVQ (1*16)(R20), V4
    MOVV (1*8)(digPtr), R20
    VMOVQ (0*16)(R20), V1
    VMOVQ (1*16)(R20), V5
    MOVV (2*8)(digPtr), R20
    VMOVQ (0*16)(R20), V2
    VMOVQ (1*16)(R20), V6
    MOVV (3*8)(digPtr), R20
    VMOVQ (0*16)(R20), V3
    VMOVQ (1*16)(R20), V7

    TRANSPOSE_MATRIX(V0, V1, V2, V3, V8, V9, V10, V11)
    TRANSPOSE_MATRIX(V4, V5, V6, V7, V8, V9, V10, V11)

    MOVV (0*8)(digPtr), R20
    VMOVQ V0, (0*16)(R20)
    VMOVQ V4, (1*16)(R20)
    MOVV (1*8)(digPtr), R20
    VMOVQ V1, (0*16)(R20)
    VMOVQ V5, (1*16)(R20)
    MOVV (2*8)(digPtr), R20
    VMOVQ V2, (0*16)(R20)
    VMOVQ V6, (1*16)(R20)
    MOVV (3*8)(digPtr), R20
    VMOVQ V3, (0*16)(R20)
    VMOVQ V7, (1*16)(R20)
    RET
