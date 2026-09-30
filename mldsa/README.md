# mldsa — ML-DSA (FIPS 204) Implementation

This package implements ML-DSA (Module-Lattice-Based Digital Signature Algorithm) as specified in [NIST FIPS 204](https://csrc.nist.gov/pubs/fips/204/final), providing three parameter sets:

| Type | Security Level | Private Key | Public Key | Signature |
|------|--------------|-------------|------------|-----------|
| `mldsa44` | Level 2 (≈AES-128) | 2560 bytes | 1312 bytes | 2420 bytes |
| `mldsa65` | Level 3 (≈AES-192) | 4032 bytes | 1952 bytes | 3309 bytes |
| `mldsa87` | Level 5 (≈AES-256) | 4896 bytes | 2592 bytes | 4627 bytes |

The implementation is derived from the Go standard library's `crypto/mldsa` package, extended with multi-architecture SIMD optimizations.

---

## Algorithm Overview

ML-DSA operates on polynomials in the ring $\mathbb{Z}_q[x]/(x^{256}+1)$ where $q = 8{,}380{,}417$. The critical hot paths are:

- **NTT (Number Theoretic Transform)**: 7-layer butterfly network converting polynomials between coefficient domain and NTT domain ($O(n \log n)$).
- **Point-wise multiplication** in NTT domain: `nttMul`, `nttMulAcc`.
- **Decompose / Hint**: `HighBits`, `LowBits`, `MakeHint`, `UseHint` — central to the signature scheme's rejection sampling.
- **Encoding/Decoding**: Variable-width bit-packing for signature components ($z$: 18/20-bit; $w_1$: 4/6-bit; hints).

Unlike ML-KEM which uses $q = 3{,}329$ (fits in 16 bits), ML-DSA uses 32-bit field elements, which significantly affects the SIMD strategy.

---

## Architecture-Specific Optimizations

### AMD64 — AVX2 (`field_amd64.s`, `encoder_amd64.go`)

**Vector width**: 256-bit YMM registers (8 × int32 per register)

**Reduction strategy**: Montgomery multiplication. Since q=8,380,417 is 23 bits wide, the products fit in 32 bits for the NTT butterfly steps. The key pattern uses `VPMULHW` (signed 16-bit multiply-high) for the Montgomery-form correction, and `VPMULD` (32-bit lane multiply, low 32 bits) for the product.

**Key operations**:

- **NTT/INTT**: 7-layer butterfly network. Y15 is permanently loaded with the constant vector `{q, q, q, q, q, q, q, q}` to avoid repeated loads. Twiddle factors come from `zetasMontgomeryAVX2` (296 entries, precomputed in Montgomery form) and `qMinusZetasMontgomeryAVX2` (296 entries for INTT). INTT levels 0–5 preorder twiddle entries as `[6,7,4,5,2,3,0,1]` to avoid `VPERMQ $0x1B` in the inner loop.

- **HighBits / decomposeSubToR0** (γ₂ = (q−1)/32): Uses the identity `HighBits(r) = (r + 127) >> 7 * 1025 >> 22 & 15`. Implemented with `VPADDD`, `VPSRLD $7`, `VPMULLD` (1025), `VPSRAD $22`, `VPAND` (15). For γ₂ = (q−1)/88: uses `VPMULLD` (11275) + `VPADDD` (2²¹) + `VPSRAD $22`.

- **MakeHint**: Computes `HighBits(rPlusZ)` and `HighBits(r)`, then uses `VPCMPEQD` + `VPANDN` to produce the one/zero hint. Processes 8 coefficients per YMM register, 32 iterations for 256 coefficients.

- **UseHint**: Applies the hint to recover the high bits with boundary correction (`r1 == 44` special case for γ₂ = (q−1)/88).

- **Encoding** (encoder):
  - `simpleBitPack4Bits` / `simpleBitPack6Bits`: Extract `w₁` bytes using `VPSHUFB` + `VPUNPCKLBW`/`VPUNPCKHBW` + `VPOR`.
  - `bitPackSignedTwoPower17` / `bitPackSignedTwoPower19`: Subtract center (2¹⁷ or 2¹⁹) from each coefficient using NEON fieldSub, then GPR-based ORR for bit-packing.
  - `bitUnpackSignedTwoPower17` / `bitUnpackSignedTwoPower19`: Use `VPSHUFB` for byte reordering + `VPSRLVD` for variable-distance right shifts to extract the 18/20-bit values into 32-bit lanes, then `fieldSub(2^17, v)`.

- **polyAddAssign / polySubAssign**: reduce_once pattern — subtract b, subtract q, check sign with `VPCMPGTD`, add back q if needed.

**Architecture notes**:
- `VPANDN Ys, Yt, Yt` in Plan 9 syntax computes `(~Yt) & Ys` (operand order is reversed from Intel syntax — verify carefully when porting).
- `MOVQ` + `VPINSRD` (VEX-encoded) for loading 9/10-byte groups in bitUnpack — mixing non-VEX SSE with VEX instructions costs ~150 cycles; always use VEX forms.

**Parallelism**: 8 coefficients per instruction. Benchmarks show 5–9× speedup over generic Go for core operations on Intel i7-13700.

---

### ARM64 — NEON (`field_arm64.s`, `encoder_arm64.go`)

**Vector width**: 128-bit V registers (4 × int32 per register)

**Reduction strategy**: A mix of Montgomery (for NTT using `SQRDMULH`) and Barrett (for other operations). Since NEON lacks a direct 32-bit multiply-high, the implementation uses `SQRDMULH Vd.4S, Vn.4S, Vm.4S` (signed saturating rounding doubling multiply-high, producing the high 32 bits of 2×a×b) with twiddle constants pre-scaled by 1/2.

**Key operations**:

- **NTT/INTT**: 7-layer butterfly network. Twiddle factors interleaved in memory for 2-load-per-cycle NEON throughput. Two vector groups processed back-to-back to hide load-use latency.

- **HighBits / decomposeSubToR0** (γ₂ = (q−1)/32):
  ```asm
  VADD V30.S4, Vx.S4, Vt.S4   // + 127
  VUSHR $7, Vt.S4, Vt.S4      // >> 7
  SQRDMULH Vi.4S, Vt.4S, Vm.4S // × 524800/2^15 ≈ ×1025/2^10 ≈ HighBits
  VAND V28.B16, Vi.B16, Vi.B16  // & 15 = r1
  ```
  `SQRDMULH` is not available as a Go asm mnemonic and must be encoded as `WORD $0x6E_mm_B4_dn`.

- **MakeHint**: Uses `VCMEQ` (compare equal → all-ones mask) + `VBIT` (bitwise insert under mask) for branchless hint computation. Processes 4 coefficients per V register.

- **UseHint**: Boundary correction with `VCMGE`/`VCMGT` + `VADD`/`VSUB`.

- **Encoding** (encoder):
  - `simpleBitPack4BitsHighBitsGamma32NEON`: `VUZP1` + `VSHL` + `VORR` to interleave and pack 4-bit values.
  - `simpleBitPack6BitsHighBitsGamma88NEON`: Multiply-high (SQRDMULH with 11275/2^15) + `UBFX` to pack 6-bit HighBits.
  - `bitPackSignedTwoPower17NEON` / `bitPackSignedTwoPower19NEON`: NEON fieldSub (center subtraction), then GPR-based `UBFX`/`ORR` for bit-packing without NEON store — avoids cross-unit transfers.
  - `bitUnpackSignedTwoPower17NEON` / `bitUnpackSignedTwoPower19NEON`: GPR `UBFX` extracts 18/20-bit values, `VMOV Rn, V.D[i]` inserts pairs into NEON registers, then NEON `fieldSub(2^17/2^19, v)` applied vectorially.

- **polyInfinityNormSignedNEON**: Sign mask via `SSHR #31` (encoded as `WORD $0x4F210464`), conditional negate with `VAND` + `VSUB`, then `VUMAXV` (reduce max across lanes, encoded as `WORD $0x6EB1A3BC`).

**Architecture notes**:
- Many NEON instructions are encoded with `WORD` directives due to Go assembler limitations. Key encodings:

  | Instruction | WORD | Notes |
  |-------------|------|-------|
  | `SSHR Vd.4S, Vn.4S, #31` | `0x4F_(64-31)_04_dn` = `0x4F210464` | sign mask (d=V4, n=V3) |
  | `SQRDMULH Vd.4S, Vn.4S, Vm.4S` | `0x6E_mm_B4_dn` | m,d,n = 5-bit reg nums |
  | `CMHI Va.S4, Vb.S4, Vc.S4` | `0x6E_cc_3C_ab` | unsigned higher |
  | `VUMAXV Sd, Vn.4S` | `0x6EB1A3BC` | reduce max d=S28, n=V27 |

- `VST1.P [V2.S4, V3.S4], (32)(R1)` — multi-register stores require **consecutive** register numbers. Reorder computations to satisfy this constraint.
- `MOVBU`/`MOVHU` for unsigned byte/halfword loads (`LDRB`/`LDRH`).
- `UBFX $lsb, Rn, $width, Rd` for unsigned bit-field extraction.

**Parallelism**: 4 coefficients per instruction (half of AVX2). Typical speedup 3–5× over generic Go.

---

### LoongArch64 — LASX (`field_loong64.s`, `encoder_loong64.go`)

**Vector width**: 256-bit XR registers (8 × int32 per register, same width as AVX2)

**Reduction strategy**: Signed Montgomery multiplication using `XVMUHW` (signed 32-bit multiply-high, the LASX equivalent of AVX2's signed `VPMULHW` for 32-bit words). This gives the same 5-instruction Montgomery kernel as AVX2 but with LASX mnemonics:

```asm
XVMULW  Xa, Xzeta, Xprod_lo   // low 32 bits of a×zeta
XVMULW  Xprod_lo, XqInv, Xt   // t = prod_lo × qInv (mod 2^32)
XVMUHW  Xa, Xzeta, Xprod_hi   // signed high 32 bits of a×zeta
XVMUHW  Xt, Xq, Xtq_hi        // signed high 32 bits of t×q
XVSUBW  Xtq_hi, Xprod_hi, Xr  // result ∈ (-q, q)
```

Where `qInv = 58728449` (= 2³² − 4236238847, the negated modular inverse of q).

**Key advantage over AVX2**: LASX's `XVMUHW` is a true signed 32-bit multiply-high (produces 8 × 32-bit high words from 8 × 32-bit × 32-bit products), exactly what ML-DSA's 32-bit field needs. AVX2 only has `VPMULHW` (16-bit) and must use a more complex sequence for 32-bit Montgomery.

**Key operations**:

- **NTT/INTT**: Structurally identical to AVX2. Directly reuses `zetasMontgomeryAVX2` twiddle table (same 8×int32 layout). The 7-layer butterfly, twiddle preordering, and reduce_once pattern are equivalent.

- **HighBits / decomposeSubToR0**: Same constants and formulas as AVX2. `XVMULW` (low 32-bit product) replaces `VPMULLD` for the HighBits multiply. `XVSRAW` (arithmetic right shift) replaces `VPSRAD`.

- **MakeHint / UseHint**: `XVSEQW` (equal comparison → all-ones mask) + `XVANDNV`/`XVORV` for branchless hint. LASX lacks `xvslt.w` (signed less-than), so comparisons use `XVSUBW + XVSRAW $31` (subtract and sign-extend) as a replacement.

- **polyAddAssign / polySubAssign**: reduce_once with `XVSUBW` + `XVSRAW $31` for the sign mask (replacing AVX2's `VPCMPGTD`).

- **Encoding** (encoder):
  - `simpleBitPack4Bits` / `simpleBitPack6Bits`: `XVSHUF4IW` for within-lane element reordering, `XVPACKEV`/`XVPACKOD` for across-lane interleave, `XVSLLW`/`XVSRLW` for alignment.
  - `bitPackSignedTwoPower17` / `bitPackSignedTwoPower19`: Center subtraction (fieldSub) with LASX, then GPR-based `XVMOVQ X.W[i], R` (xvpickve2gr.w) for per-element extraction and bit-ORing.
  - `bitUnpackSignedTwoPower17` / `bitUnpackSignedTwoPower19`: `XVMOVQ R, X.W[i]` (xvinsgr2vr.w) to build LASX vectors from extracted GPR values, then LASX fieldSub. Eliminates store-forwarding round-trips compared to load-modify-store.

- **polyInfinityNormSigned**: `XVSRAW $31` for sign mask + `XVSUBW`/`XVANDNV` for conditional negate + reduction using `XVMAXW` or scalar `XVMOVQ X.W[i], R`.

**Architecture notes**:
- LASX operates on XR registers (X0–X31, 256-bit). The lower 128 bits are accessible as the corresponding V register for LSX operations.
- Several LASX instructions are not yet available as Go asm mnemonics in Go 1.24 and require `WORD` encoding:
  - `xvpermi.q` (cross-128-bit-lane permute): `WORD $0x...`
  - `xvshuf.w` (general word shuffle): `WORD $0x...`
  - `xvbitsel.v` (3-operand bitselect): Replaced by `XVANDV`/`XVANDNV`/`XVORV` (3 instructions)
- Go 1.25 (master) adds `XVMOVQ X.W[idx], R` and `XVMOVQ R, X.W[idx]` element insertion — use these instead of store-forwarding patterns when targeting Go ≥ 1.25.
- Twiddle table is shared with `field_amd64.go` as both use 8 × int32 per vector register.

**Parallelism**: 8 coefficients per instruction (same as AVX2). Expected speedup 5–7× over generic Go, matching AVX2 for NTT-heavy workloads due to the simpler Montgomery kernel.

---

### RISC-V64 — RVV (`field_riscv64.s`, `encoder_riscv64.go`)

**Requirements**: Go 1.26+ (build tag `go1.26`) and a CPU implementing the RVV 1.0 vector extension (`cpu.RISCV64.HasV`).

**Vector width**: Variable — the RVV vector length `VLEN` is implementation-defined. All loops strip-mine with `VSETVLI`, so the code is VLEN-agnostic and works on any `VLEN ≥ 128`. With `SEW=32`, group multipliers M4 (polyAdd/Sub, norm), M2 (nttMul family) and M1 (NTT butterflies) give a vector length in {16, 32, 64, 128, 256} coefficients, all of which divide 256 exactly.

**Reduction strategy**: Montgomery multiplication with an explicit hi/lo split. RVV has no fused 32×32 multiply that yields both halves, so the kernel computes the low and high 32 bits of `a*b` with two separate instructions (`VMULVV`, `VMULHUVV` — unsigned multiply-high, since operands are canonical residues in [0, q)). Because `high32(a*b)` and `high32(m*q)` are accumulated separately, the carry from `low32(a*b) + low32(m*q)` is not automatic and must be fixed up explicitly:

```asm
VMULVV   b, a, lo            // low 32 bits of a*b
VMULHUVV b, a, dst           // high 32 bits of a*b
VMULVX   QNEGINV, lo, m      // m = lo * (-q^-1) mod 2^32
VMINUVX  ONE, lo, lo         // lo = carry bit (0 or 1)
VMULHUVX Q, m, m             // high 32 bits of m*q
VADDVV   lo, dst, dst
VADDVV   m, dst, dst
REDUCE_ONCE_RVV(dst, lo)     // reduce x < 2q into [0, q)
```

Where `QNEGINV = 4236238847` (the negated modular inverse of q mod 2³²). The `REDUCE_ONCE_RVV` macro has no compare instruction — it extracts the sign with `VSRAVI $31` and masks with `VANDVX Q`, the same sign-mask pattern used for `polySubAssign`.

**Key operations**:

- **NTT/INTT**: The upper levels (len = 128…8) are strip-mined M1 chunk loops with the twiddle loaded per group as a scalar (`MONT_MUL_HILO_VX`). The bottom levels (len = 4, 2, 1) use segment loads `VLSEG8E32V` / `VLSEG4E32V` / `VLSEG2E32V` to de-interleave, so each vector register holds the same position of 8/4/2 groups and one vector-zeta butterfly (`MONT_MUL_HILO_VZ`) processes all of them together; `VSSEG*E32V` re-interleaves on store. INTT mirrors this structure using `zetasMontgomeryInverse` (the reversed table, built at init) and finishes with a final scale by `invDegreeMontgomery = 41978`.

- **nttMatRowVecMul**: For each RVV chunk, all row products are accumulated in registers (no memory round-trip) and written to dst once per chunk.

- **HighBits / decomposeSubToR0**: Same multiply-shift constants as AVX2 — `(x + 127) >> 7 * 1025 + 2²¹ >> 22 & 15` for γ₂ = (q−1)/32, and `11275`, `2²³`, `>> 24` plus the `r1 == 44 → 0` clamp (`VRSUBVX 43` + sign mask + `VXORVV`) for γ₂ = (q−1)/88. The r0 center-lift around q/2 uses `VRSUBVX qMinus1Div2` + sign mask + `VSUBVV`.

- **MakeHint**: RVV's dedicated mask registers replace the AVX2 compare/andn trick — `VMSNEVV` writes a comparison result into mask register `V0`, then `VMERGEVIM $1` selects between 1 and 0 per lane to produce the 0/1 hint.

- **UseHint**: Branchless: `delta = h ? (r0 > 0 ? 1 : 2γ₂−1) : 0` built from `VRSUBVX ZERO` sign masks and immediate `VANDVI`/`VXORVI`. Inputs are loaded before any store so exact output aliasing (`out == h`) is safe.

- **polyInfinityNorm / polyInfinityNormSigned**: M4 groups. Signed norm: `abs(a)` via sign mask (`VXORVV` + `VSUBVV`); unsigned norm: centering `min(a, q−a)` via `VRSUBVX Q` + `VMINUVV`. Per-lane maxima are kept in registers across chunks (`VMAXUVV`), and the horizontal reduction runs exactly once at the end with `VREDMAXUVS`.

- **Encoding** (encoder):
  - `simpleBitPack4Bits` / `simpleBitPack4BitsHighBitsGamma32`: `VLSEG2E32V` loads even/odd coefficients into two vectors, HighBits is fused into the packing loop, nibbles are merged with `VSLLVI $4` + `VORVV`, then narrowed in two steps via `VNSRLWX` (E32→E16→E8) and stored with `VSE8V`.
  - `simpleBitPack6Bits` / `simpleBitPack6BitsHighBitsGamma88`: 4 coefficients → 3 bytes; shift/or reassembly, the same two-step narrowing, and `VSSEG3E8V` (segment-3 byte store).
  - `bitPackSignedTwoPower17` / `bitUnpackSignedTwoPower17`: Hybrid approach — the vector unit performs the center subtraction (`fieldSub(2¹⁷, v)`), then GPR instructions pack/unpack four 18-bit values per 9-byte group (`SLL $18/$36/$54` + `OR` + trailing `MOVB`), spilling through an 8-element stack buffer. 18-bit values do not align with byte lanes, so this mirrors the GPR-based bit-packing strategy of AVX2/NEON.
  - `bitPackSignedTwoPower19` / `bitUnpackSignedTwoPower19`: Fully vectorized — 2 coefficients ↔ 5 bytes using `VNSRLWX` narrowing + `VSSEG5E8V` on pack, and `VLSEG5E8V` + `VZEXTVF4` zero-extend + shift/or on unpack, followed by vector `fieldSub(2¹⁹, v)`.

**Architecture notes**:
- The Go 1.26 assembler has native RVV mnemonics for everything used here — no `WORD`-encoded instructions are needed (unlike ARM64/LoongArch64).
- RVV comparisons produce mask-register results, not vector masks: use `VMSNE*`/`VMERGE*` (or sign-mask arithmetic) instead of `VPCMPGTD`-style all-ones lanes.
- There is no fused 32×32→64 multiply: the hi/lo Montgomery kernel needs the explicit carry fixup `VMINUVX ONE, lo, lo` described above.
- Segment loads/stores (`VLSEGnE32V`, `VSSEGN*`) are the RVV replacement for the interleave/de-interleave instructions (`VUZP1`, `XVSHUF4IW`, `xvpermi.q`) used on other architectures.
- Twiddle tables are shared with the generic Go code: NTT consumes `zetasMontgomery` directly (skipping entry 0), and the INTT table is simply the reversed order — no AVX2-style preordering is required because segment loads tolerate arbitrary group alignment.

**Parallelism**: `VLEN/32` coefficients per instruction (at least 4, up to 256 with large VLEN). Performance scales with `VLEN` and the machine's vector issue width; measure on target hardware with `go test -bench=RVV`.

---

## Comparison Summary

| Aspect | AVX2 | NEON | LASX | RVV |
|--------|------|------|------|-----|
| Field element width | 32-bit | 32-bit | 32-bit | 32-bit |
| Coefficients/register | 8 | 4 | 8 | `VLEN/32` (≥ 4, strip-mined) |
| Montgomery strategy | `VPMULHW` (16-bit mul-high) | `SQRDMULH` (approx) | `XVMUHW` (true 32-bit signed mul-high) | `VMULVV` + `VMULHUVV` (hi/lo split) |
| Montgomery kernel | ~12 instructions | ~8 instructions | ~5 instructions | ~8 instructions (+ carry fixup) |
| HighBits multiply | `VPMULLD` (low 32) | `SQRDMULH` × scaled const | `XVMULW` (low 32) | `VMULVX` (low 32, scalar × vector) |
| Compare (signed < 0) | `VPCMPGTD` | `SSHR #31` (WORD) | `XVSRAW $31` | `VSRAVI $31` |
| Twiddle table shared? | Own (`zetasMontgomeryAVX2`) | Own | Reuses AVX2 table | Reuses generic table (INTT reversed at init) |
| WORD-encoded instrs | Few (bitUnpack path) | Many (`SSHR`, `SQRDMULH`, `CMHI`, `VUMAXV`) | Some (`xvpermi.q`, `xvshuf.w`) | None (native mnemonics in Go 1.26) |

---

## Performance Summary

Approximate speedup over generic Go (`go test -bench=. -benchtime=3s ./mldsa/`):

| Operation | Generic | AVX2 | NEON | LASX | RVV |
|-----------|---------|------|------|------|-----|
| NTT Forward | 1× | ~7× | ~4× | ~6× | — |
| NTT Inverse | 1× | ~6× | ~3.5× | ~5× | — |
| polyAddAssign | 1× | ~8× | ~4× | ~7× | — |
| nttMulAcc | 1× | ~6× | ~3.5× | ~5× | — |
| decomposeSubToR0 | 1× | ~7× | ~4× | ~6× | — |
| makeHintPoly | 1× | ~9× | ~5× | ~7× | — |
| simpleBitPack4Bits | 1× | ~7× | ~4× | ~6× | — |
| bitPackSigned17 | 1× | ~2.5× | ~2× | ~3× | — |
| bitUnpackSigned17 | 1× | ~1.6× | ~1.5× | ~2× | — |
| Sign (mldsa44) | — | ~3× | ~2× | ~2.5× | — |
| Verify (mldsa44) | — | ~4× | ~2.5× | ~3× | — |

*Note: Actual performance depends on CPU microarchitecture and memory hierarchy. Measure on target hardware. RVV numbers are omitted because they scale with the implementation-defined `VLEN`; run `go test -bench=RVV -benchtime=3s ./mldsa/` on target hardware.*

---

## Files

| File | Purpose |
|------|---------|
| `field.go` | Algorithm core, generic Go implementation, constant definitions |
| `field_barrett.go` | Barrett reduction helpers (shared across architectures) |
| `field_noasm.go` | Pure-Go fallback dispatch |
| `field_amd64.go` | AMD64 function declarations, twiddle table init |
| `field_amd64.s` | AMD64 AVX2 assembly (NTT, decompose, hint, polyAdd/Sub, norm) |
| `field_arm64.go` | ARM64 function declarations, twiddle table init |
| `field_arm64.s` | ARM64 NEON assembly |
| `field_loong64.go` | LoongArch64 function declarations, twiddle table init |
| `field_loong64.s` | LoongArch64 LASX assembly |
| `field_riscv64.go` | RISC-V64 function declarations, inverse twiddle table init |
| `field_riscv64.s` | RISC-V64 RVV assembly (NTT, decompose, hint, polyAdd/Sub, norm) |
| `encoder.go` | Generic encoding/decoding (bit-pack/unpack) |
| `encoder_noasm.go` | Pure-Go dispatch |
| `encoder_amd64.go` | AMD64 encoder dispatch |
| `encoder_arm64.go` | ARM64 encoder dispatch |
| `encoder_loong64.go` | LoongArch64 encoder dispatch |
| `encoder_loong64.s` | LoongArch64 LASX encoder assembly |
| `encoder_riscv64.go` | RISC-V64 encoder dispatch |
| `encoder_riscv64.s` | RISC-V64 RVV encoder assembly |
| `sample.go` | ExpandA, ExpandS, ExpandMask — polynomial sampling |
| `compress.go` | compress/decompress for w₁ |
| `mldsa44.go` | ML-DSA-44 public API |
| `mldsa65.go` | ML-DSA-65 public API |
| `mldsa87.go` | ML-DSA-87 public API |

---

## Build Tags

```shell
# Default: SIMD assembly enabled (if supported)
go build ./mldsa/

# Pure-Go fallback (no assembly)
go build -tags=purego ./mldsa/

# Cross-compile for target architecture
GOOS=linux GOARCH=arm64   go build ./mldsa/
GOOS=linux GOARCH=loong64 go build ./mldsa/
GOOS=linux GOARCH=riscv64 go build ./mldsa/  # requires Go 1.26+

# Run benchmarks
go test -bench=. -benchtime=3s ./mldsa/

# Run architecture-specific benchmarks
go test -bench=BenchmarkAMD64 -benchtime=3s ./mldsa/
go test -bench=BenchmarkARM64 -benchtime=3s ./mldsa/
go test -bench=BenchmarkLoong64 -benchtime=3s ./mldsa/
go test -bench=RVV -benchtime=3s ./mldsa/  # requires Go 1.26+ and riscv64
```

---

## References

- [NIST FIPS 204](https://csrc.nist.gov/pubs/fips/204/final) — ML-DSA specification
- [CRYSTALS-Dilithium reference implementation](https://github.com/pq-crystals/dilithium) — original algorithm and AVX2 assembly reference
- [LASX Instruction Set Manual](https://loongson.github.io/LoongArch-Documentation/LoongArch-Vol1-EN.html) — LoongArch ISA reference
