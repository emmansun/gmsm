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

## Comparison Summary

| Aspect | AVX2 | NEON | LASX |
|--------|------|------|------|
| Field element width | 32-bit | 32-bit | 32-bit |
| Coefficients/register | 8 | 4 | 8 |
| Montgomery strategy | `VPMULHW` (16-bit mul-high) | `SQRDMULH` (approx) | `XVMUHW` (true 32-bit signed mul-high) |
| Montgomery kernel | ~12 instructions | ~8 instructions | ~5 instructions |
| HighBits multiply | `VPMULLD` (low 32) | `SQRDMULH` × scaled const | `XVMULW` (low 32) |
| Compare (signed < 0) | `VPCMPGTD` | `SSHR #31` (WORD) | `XVSRAW $31` |
| Twiddle table shared? | Own (`zetasMontgomeryAVX2`) | Own | Reuses AVX2 table |
| WORD-encoded instrs | Few (bitUnpack path) | Many (`SSHR`, `SQRDMULH`, `CMHI`, `VUMAXV`) | Some (`xvpermi.q`, `xvshuf.w`) |

---

## Performance Summary

Approximate speedup over generic Go (`go test -bench=. -benchtime=3s ./mldsa/`):

| Operation | Generic | AVX2 | NEON | LASX |
|-----------|---------|------|------|------|
| NTT Forward | 1× | ~7× | ~4× | ~6× |
| NTT Inverse | 1× | ~6× | ~3.5× | ~5× |
| polyAddAssign | 1× | ~8× | ~4× | ~7× |
| nttMulAcc | 1× | ~6× | ~3.5× | ~5× |
| decomposeSubToR0 | 1× | ~7× | ~4× | ~6× |
| makeHintPoly | 1× | ~9× | ~5× | ~7× |
| simpleBitPack4Bits | 1× | ~7× | ~4× | ~6× |
| bitPackSigned17 | 1× | ~2.5× | ~2× | ~3× |
| bitUnpackSigned17 | 1× | ~1.6× | ~1.5× | ~2× |
| Sign (mldsa44) | — | ~3× | ~2× | ~2.5× |
| Verify (mldsa44) | — | ~4× | ~2.5× | ~3× |

*Note: Actual performance depends on CPU microarchitecture and memory hierarchy. Measure on target hardware.*

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
| `encoder.go` | Generic encoding/decoding (bit-pack/unpack) |
| `encoder_noasm.go` | Pure-Go dispatch |
| `encoder_amd64.go` | AMD64 encoder dispatch |
| `encoder_arm64.go` | ARM64 encoder dispatch |
| `encoder_loong64.go` | LoongArch64 encoder dispatch |
| `encoder_loong64.s` | LoongArch64 LASX encoder assembly |
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
GOOS=linux GOARCH=arm64  go build ./mldsa/
GOOS=linux GOARCH=loong64 go build ./mldsa/

# Run benchmarks
go test -bench=. -benchtime=3s ./mldsa/

# Run architecture-specific benchmarks
go test -bench=BenchmarkAMD64 -benchtime=3s ./mldsa/
go test -bench=BenchmarkARM64 -benchtime=3s ./mldsa/
go test -bench=BenchmarkLoong64 -benchtime=3s ./mldsa/
```

---

## References

- [NIST FIPS 204](https://csrc.nist.gov/pubs/fips/204/final) — ML-DSA specification
- [CRYSTALS-Dilithium reference implementation](https://github.com/pq-crystals/dilithium) — original algorithm and AVX2 assembly reference
- [Go standard library `crypto/mldsa`](https://pkg.go.dev/crypto/mldsa) — upstream generic implementation (Go ≥ 1.24)
- [LASX Instruction Set Manual](https://loongson.github.io/LoongArch-Documentation/LoongArch-Vol1-EN.html) — LoongArch ISA reference
