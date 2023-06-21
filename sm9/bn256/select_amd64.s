//go:build amd64 && !purego
// +build amd64,!purego

#include "textflag.h"

#define res_ptr DI
#define x_ptr SI
#define y_ptr CX

// func gfP12MovCond(res, a, b *gfP12, cond int)
TEXT ·gfP12MovCond(SB),NOSPLIT,$0
	MOVQ res+0(FP), res_ptr
	MOVQ a+8(FP), x_ptr
	MOVQ b+16(FP), y_ptr
	MOVQ cond+24(FP), X12

	CMPB ·supportAVX2+0(SB), $0x01
	JEQ  move_avx2
	
	PXOR X13, X13
	PSHUFD $0, X12, X12
	PCMPEQL X13, X12

	MOVOU X12, X0
	MOVOU (16*0)(x_ptr), X6
	PANDN X6, X0

	MOVOU X12, X1
	MOVOU (16*1)(x_ptr), X7
	PANDN X7, X1

	MOVOU X12, X2
	MOVOU (16*2)(x_ptr), X8
	PANDN X8, X2

	MOVOU X12, X3
	MOVOU (16*3)(x_ptr), X9
	PANDN X9, X3

	MOVOU X12, X4
	MOVOU (16*4)(x_ptr), X10
	PANDN X10, X4

	MOVOU X12, X5
	MOVOU (16*5)(x_ptr), X11
	PANDN X11, X5

	MOVOU (16*0)(y_ptr), X6
	MOVOU (16*1)(y_ptr), X7
	MOVOU (16*2)(y_ptr), X8
	MOVOU (16*3)(y_ptr), X9
	MOVOU (16*4)(y_ptr), X10
	MOVOU (16*5)(y_ptr), X11

	PAND X12, X6
	PAND X12, X7
	PAND X12, X8
	PAND X12, X9
	PAND X12, X10
	PAND X12, X11

	PXOR X6, X0
	PXOR X7, X1
	PXOR X8, X2
	PXOR X9, X3
	PXOR X10, X4
	PXOR X11, X5

	MOVOU X0, (16*0)(res_ptr)
	MOVOU X1, (16*1)(res_ptr)
	MOVOU X2, (16*2)(res_ptr)
	MOVOU X3, (16*3)(res_ptr)
	MOVOU X4, (16*4)(res_ptr)
	MOVOU X5, (16*5)(res_ptr)

	MOVOU X12, X0
	MOVOU (16*6)(x_ptr), X6
	PANDN X6, X0

	MOVOU X12, X1
	MOVOU (16*7)(x_ptr), X7
	PANDN X7, X1

	MOVOU X12, X2
	MOVOU (16*8)(x_ptr), X8
	PANDN X8, X2

	MOVOU X12, X3
	MOVOU (16*9)(x_ptr), X9
	PANDN X9, X3

	MOVOU X12, X4
	MOVOU (16*10)(x_ptr), X10
	PANDN X10, X4

	MOVOU X12, X5
	MOVOU (16*11)(x_ptr), X11
	PANDN X11, X5

	MOVOU (16*6)(y_ptr), X6
	MOVOU (16*7)(y_ptr), X7
	MOVOU (16*8)(y_ptr), X8
	MOVOU (16*9)(y_ptr), X9
	MOVOU (16*10)(y_ptr), X10
	MOVOU (16*11)(y_ptr), X11

	PAND X12, X6
	PAND X12, X7
	PAND X12, X8
	PAND X12, X9
	PAND X12, X10
	PAND X12, X11

	PXOR X6, X0
	PXOR X7, X1
	PXOR X8, X2
	PXOR X9, X3
	PXOR X10, X4
	PXOR X11, X5

	MOVOU X0, (16*6)(res_ptr)
	MOVOU X1, (16*7)(res_ptr)
	MOVOU X2, (16*8)(res_ptr)
	MOVOU X3, (16*9)(res_ptr)
	MOVOU X4, (16*10)(res_ptr)
	MOVOU X5, (16*11)(res_ptr)

	MOVOU X12, X0
	MOVOU (16*12)(x_ptr), X6
	PANDN X6, X0

	MOVOU X12, X1
	MOVOU (16*13)(x_ptr), X7
	PANDN X7, X1

	MOVOU X12, X2
	MOVOU (16*14)(x_ptr), X8
	PANDN X8, X2

	MOVOU X12, X3
	MOVOU (16*15)(x_ptr), X9
	PANDN X9, X3

	MOVOU X12, X4
	MOVOU (16*16)(x_ptr), X10
	PANDN X10, X4

	MOVOU X12, X5
	MOVOU (16*17)(x_ptr), X11
	PANDN X11, X5

	MOVOU (16*12)(y_ptr), X6
	MOVOU (16*13)(y_ptr), X7
	MOVOU (16*14)(y_ptr), X8
	MOVOU (16*15)(y_ptr), X9
	MOVOU (16*16)(y_ptr), X10
	MOVOU (16*17)(y_ptr), X11

	PAND X12, X6
	PAND X12, X7
	PAND X12, X8
	PAND X12, X9
	PAND X12, X10
	PAND X12, X11

	PXOR X6, X0
	PXOR X7, X1
	PXOR X8, X2
	PXOR X9, X3
	PXOR X10, X4
	PXOR X11, X5

	MOVOU X0, (16*12)(res_ptr)
	MOVOU X1, (16*13)(res_ptr)
	MOVOU X2, (16*14)(res_ptr)
	MOVOU X3, (16*15)(res_ptr)
	MOVOU X4, (16*16)(res_ptr)
	MOVOU X5, (16*17)(res_ptr)

	MOVOU X12, X0
	MOVOU (16*18)(x_ptr), X6
	PANDN X6, X0

	MOVOU X12, X1
	MOVOU (16*19)(x_ptr), X7
	PANDN X7, X1

	MOVOU X12, X2
	MOVOU (16*20)(x_ptr), X8
	PANDN X8, X2

	MOVOU X12, X3
	MOVOU (16*21)(x_ptr), X9
	PANDN X9, X3

	MOVOU X12, X4
	MOVOU (16*22)(x_ptr), X10
	PANDN X10, X4

	MOVOU X12, X5
	MOVOU (16*23)(x_ptr), X11
	PANDN X11, X5

	MOVOU (16*18)(y_ptr), X6
	MOVOU (16*19)(y_ptr), X7
	MOVOU (16*20)(y_ptr), X8
	MOVOU (16*21)(y_ptr), X9
	MOVOU (16*22)(y_ptr), X10
	MOVOU (16*23)(y_ptr), X11

	PAND X12, X6
	PAND X12, X7
	PAND X12, X8
	PAND X12, X9
	PAND X12, X10
	PAND X12, X11

	PXOR X6, X0
	PXOR X7, X1
	PXOR X8, X2
	PXOR X9, X3
	PXOR X10, X4
	PXOR X11, X5

	MOVOU X0, (16*18)(res_ptr)
	MOVOU X1, (16*19)(res_ptr)
	MOVOU X2, (16*20)(res_ptr)
	MOVOU X3, (16*21)(res_ptr)
	MOVOU X4, (16*22)(res_ptr)
	MOVOU X5, (16*23)(res_ptr)

	RET

move_avx2:
	VPXOR Y13, Y13, Y13
	VPBROADCASTD X12, Y12
	VPCMPEQD Y13, Y12, Y12

	VPANDN (32*0)(x_ptr), Y12, Y0 
	VPANDN (32*1)(x_ptr), Y12, Y1
	VPANDN (32*2)(x_ptr), Y12, Y2
	VPANDN (32*3)(x_ptr), Y12, Y3
	VPANDN (32*4)(x_ptr), Y12, Y4
	VPANDN (32*5)(x_ptr), Y12, Y5

	VPAND (32*0)(y_ptr), Y12, Y6
	VPAND (32*1)(y_ptr), Y12, Y7
	VPAND (32*2)(y_ptr), Y12, Y8
	VPAND (32*3)(y_ptr), Y12, Y9
	VPAND (32*4)(y_ptr), Y12, Y10
	VPAND (32*5)(y_ptr), Y12, Y11

	VPXOR Y6, Y0, Y0
	VPXOR Y7, Y1, Y1
	VPXOR Y8, Y2, Y2
	VPXOR Y9, Y3, Y3
	VPXOR Y10, Y4, Y4
	VPXOR Y11, Y5, Y5

	VMOVDQU Y0, (32*0)(res_ptr)
	VMOVDQU Y1, (32*1)(res_ptr)
	VMOVDQU Y2, (32*2)(res_ptr)
	VMOVDQU Y3, (32*3)(res_ptr)
	VMOVDQU Y4, (32*4)(res_ptr)
	VMOVDQU Y5, (32*5)(res_ptr)

	VPANDN (32*6)(x_ptr), Y12, Y0 
	VPANDN (32*7)(x_ptr), Y12, Y1
	VPANDN (32*8)(x_ptr), Y12, Y2
	VPANDN (32*9)(x_ptr), Y12, Y3
	VPANDN (32*10)(x_ptr), Y12, Y4
	VPANDN (32*11)(x_ptr), Y12, Y5

	VPAND (32*6)(y_ptr), Y12, Y6
	VPAND (32*7)(y_ptr), Y12, Y7
	VPAND (32*8)(y_ptr), Y12, Y8
	VPAND (32*9)(y_ptr), Y12, Y9
	VPAND (32*10)(y_ptr), Y12, Y10
	VPAND (32*11)(y_ptr), Y12, Y11

	VPXOR Y6, Y0, Y0
	VPXOR Y7, Y1, Y1
	VPXOR Y8, Y2, Y2
	VPXOR Y9, Y3, Y3
	VPXOR Y10, Y4, Y4
	VPXOR Y11, Y5, Y5

	VMOVDQU Y0, (32*6)(res_ptr)
	VMOVDQU Y1, (32*7)(res_ptr)
	VMOVDQU Y2, (32*8)(res_ptr)
	VMOVDQU Y3, (32*9)(res_ptr)
	VMOVDQU Y4, (32*10)(res_ptr)
	VMOVDQU Y5, (32*11)(res_ptr)

	VZEROUPPER
	RET
