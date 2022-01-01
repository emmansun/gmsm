#include "textflag.h"

// func tblAsm(in, imm, out *byte)
TEXT ·tblAsm(SB),NOSPLIT,$0
  MOVD	in+0(FP), R8
  MOVD  imm+8(FP), R9
  MOVD  out+16(FP), R10

  VLD1 (R8), [V0.B16]
  VLD1 (R9), [V1.B16]

  VTBL V1.B16, [V0.B16], V2.B16
  VST1 [V2.B16], (R10)
  RET
  