# mlkem — ML-KEM (FIPS 203) Implementation

This package implements ML-KEM (Module-Lattice-Based Key-Encapsulation Mechanism) as specified in [NIST FIPS 203](https://csrc.nist.gov/pubs/fips/203/final), providing three parameter sets:

| Type | Security Level | Key Size | Ciphertext |
|------|--------------|---------|-----------|
| `mlkem512` | Level 1 (≈AES-128) | 800 bytes | 768 bytes |
| `mlkem768` | Level 3 (≈AES-192) | 1184 bytes | 1088 bytes |
| `mlkem1024` | Level 5 (≈AES-256) | 1568 bytes | 1568 bytes |

The implementation is derived from the Go standard library's `crypto/mlkem` package, extended with multi-architecture SIMD optimizations.

---

## Architecture-Specific Optimizations

The hot path (`field_*.go` / `field_*.s`) is optimized with SIMD assembly for four architectures. All optimized paths fall back to a pure-Go generic implementation on unsupported platforms or when the `purego` build tag is set.

### AMD64 — AVX2 (`field_amd64.s`)

**Vector width**: 256-bit YMM registers (16 × int16 per register)

**Reduction strategy**: Montgomery multiplication using `VPMULHW` (signed 16-bit multiply-high, produces the high 16 bits of the 32-bit product directly).

**Key operations**:
- **NTT/INTT**: 7-layer butterfly network with Barrett reduction. All 256 coefficients processed in 16-wide SIMD lanes.
- **nttMulAcc**: Point-wise NTT-domain multiplication using Montgomery multiply-high (`VPMULHW` + `VPMULD`) without scalar fallback.
- **CBD sampling** (η=2, η=3): Vectorized bit-parallel popcount with `VPSHUFB` byte shuffle for S-box-style counting.
- **rejUniform**: Vectorized extraction and conditional acceptance of 12-bit values.
- **Compress/decompress**: SIMD bit-packing for all bit widths (1, 4, 5, 10, 11 bits).

**Parallelism**: Processes 16 coefficients per instruction. AVX2 targets Intel Haswell (2013) and later, AMD Zen (2017) and later.

---

### ARM64/NEON (`field_arm64.s`)

**Vector width**: 128-bit V registers (8 × int16 per register)

**Reduction strategy**: Montgomery multiplication using `SQRDMULH` (signed saturating rounding doubling multiply-high), which approximates the high 16 bits of the product with a correction factor baked into the twiddle table.

**Key operations**:
- **NTT/INTT**: 7-layer butterfly network. Layers 1–5 use precomputed twiddle tables interleaved for NEON's 2-load-per-cycle throughput.
- **nttMulAcc**: `SQRDMULH`-based Montgomery multiplication. Two vectors processed simultaneously to hide load latency.
- **CBD sampling** (η=2, η=3): Vectorized popcount using `VCNT` (population count per byte) + `VADDLP` (pairwise add) to accumulate bit counts per coefficient.
- **rejUniform**: NEON vectorized extraction using `VTBL` byte permutation.
- **Compress/decompress**: NEON bit-packing using `VSHL`/`VSHR` and `VZIP`/`VUZP`.

**Architecture notes**: Some instructions are encoded with `WORD` directives to work around Go assembler limitations:
- `UMULL`/`UMULL2`: Encoded as `WORD $(0x...)` (Go asm lacks these mnemonics)
- `VBIC` (vector AND-NOT): Encoded as `WORD $(0x4E601C00 | ...)` 

**Parallelism**: Processes 8 coefficients per instruction. Targets ARMv8-A (all 64-bit ARM cores).

---

### LoongArch64 — LASX (`field_loong64.s`)

**Vector width**: 256-bit XR registers (16 × int16 per register, same as AVX2)

**Reduction strategy**: Montgomery multiplication using `XVMUH.H` (signed 16-bit multiply-high, LoongArch LSX/LASX equivalent of `VPMULHW`).

**Key operations**:
- **NTT/INTT**: 7-layer butterfly network structurally equivalent to the AVX2 implementation. LASX `XVMUH.H` + `XVSLLH`/`XVSRLH` replaces AVX2 `VPMULHW`/`VPMULD`.
- **nttMulAcc**: Point-wise NTT-domain multiplication using `XVMUH.H` Montgomery.
- **CBD2 sampling** (η=2): Bit-parallel popcount using `XVANDI` + `XVSUB` + `XVSRLH`.
- **CBD3 sampling** (η=3): Bit-parallel popcount using mask `0x249249` to simultaneously compute popcount of all 3-bit groups. The formula `(s + 0x6DB6DB) - (s >> 3)` combines the bias addition and subtraction in a single step, avoiding explicit separation of 'a' and 'b' bit groups. The 3-byte input groups are rearranged into 32-bit lanes using `XVSHUF_B` with a precomputed shuffle table (`cbd3Shuf`).
- **rejUniform**: LASX vectorized 12-bit extraction.
- **Compress/decompress**: LASX bit-packing.

**Architecture notes**: Uses both 128-bit LSX (`V` registers) and 256-bit LASX (`X` registers). LASX requires LoongArch LA64 with LASX extension (LA464 processor, LoongArch 3A5000 and later).

**Key design difference from AVX2**: LASX `XVSHUF_B` is a 3-operand byte-level shuffle that can select from two source vectors and fill with zero — used extensively for byte-level permutations without needing separate zero-masking.

---

### ppc64le — VMX/AltiVec (`field_ppc64le.s`)

**Vector width**: 128-bit V registers (8 × int16 per register, same as NEON)

**Reduction strategy**: Barrett reduction. Unlike the other architectures, ppc64le's VMX has no native signed 16-bit multiply-high instruction. Barrett reduction uses 32-bit intermediate products via `VMULEUH`/`VMULOUH` (even/odd lane 16×16→32 multiply) with a shift-4 trick to avoid 32-bit overflow:

```
shift-4 Barrett:
  P = coeff × zeta  (16-bit × 16-bit → 32-bit, max q² ≈ 11M)
  P' = P >> 4       (max ≈ 692K, fits in uint32)
  Q = (P' × 5039) >> 20  (quotient estimate, equivalent to P × 5039 >> 24)
  r = P - Q × q    (remainder ∈ [0, 2q))
```

This avoids the 32-bit overflow that would occur with direct `VMULUWM(P, 5039)` since 11M × 5039 > 2³².

**Key operations**:
- **NTT/INTT**: 7-layer butterfly network with Barrett reduction. `VMULEUH`/`VMULOUH` split even/odd lanes; `XXMRGLW`/`XXMRGHW` (VSX) reassemble the interleaved products.
- **nttMulAcc**: Point-wise multiplication using 64-bit Barrett (`VMULEUW`/`VMULOUW` + `VSRD`).
- **CBD2 sampling** (η=2): VMX vectorized bit-parallel popcount. Byte-level operations with `VPERM` for STXVD2X-aware byte reordering. Constants `{0x0F×16}` and `{0x03×16}` generated via `VSPLTISB` rather than loaded from memory.
- **CBD3 sampling** (η=3): VMX vectorized bit-parallel popcount using `VAND`/`VSRW`/`VADDUWM` with mask `0x249249`. Two 12-byte input groups (Block A, Block B) processed per loop iteration using two overlapping 16-byte `LXVD2X` loads covering 24 bytes. The `cbd3ShufA` VPERM mask rearranges bytes into 32-bit lanes. The `extractLoMask`/`extractHiMask` VPERM masks combine coefficient extraction with STXVD2X endian correction in a single step. **Critical constraint**: these masks assume that `coeff+3 ∈ [0, 6]` (i.e., high bytes of the source halfwords are 0x00). The VSUBUHM-3 operation must come **after** VPERM, not before.
- **rejUniform**: Scalar implementation with conditional branches (VMX offers no advantage for this operation's access pattern). Uses `ANDCC` for the 12-bit mask (required for immediate AND in Go ppc64 asm).
- **Compress/decompress**: Scalar bit-packing using `RLDICL` parallel extraction and `MFVSRD`/`MFVSRLD` to transfer VMX results to GPRs.

**Architecture notes**:
- `LXVD2X` reverses bytes within each 8-byte group on ppc64le. Pure element-wise operations (polyAdd/Sub) are unaffected (load and store both reverse, cancelling out). Operations that require knowing which element is at which position need `VPERM` correction.
- VS32–VS63 are aliases for V0–V31 (VSX = VS0-VS63, VMX V0-V31 = VS32-VS63). The instruction `STXVD2X VS45, ...` stores V13.
- All ppc64le Linux systems with Go support require at least POWER8, which guarantees VMX+VSX availability — no runtime CPU feature detection is needed.
- The constant table `cbd3VMXConsts` is 96 bytes (reduced from 128 by generating `mask7` and `const3` via `VSPLTISW`/`VSPLTISH` instead of loading from memory).

**Parallelism**: 8 coefficients per instruction (same as NEON). Performance is generally 60–80% of NEON due to the Barrett vs. Montgomery overhead and the lack of signed multiply-high.

---

## Comparison Summary

| Aspect | AVX2 | NEON | LASX | VMX |
|--------|------|------|------|-----|
| Field element width | 16-bit | 16-bit | 16-bit | 16-bit |
| Coefficients/register | 16 | 8 | 16 | 8 |
| Reduction strategy | Montgomery (`VPMULHW`) | Montgomery (`SQRDMULH`) | Montgomery (`XVMUH.H`) | Barrett (shift-4 trick) |
| Signed multiply-high | `VPMULHW` (16-bit) | `SQRDMULH` (approx) | `XVMUH.H` (exact 16-bit) | None — use `VMULEUH`/`VMULOUH` |
| CBD sampling method | `VPSHUFB` popcount | `VCNT`+`VADDLP` popcount | `XVANDI`+`XVSHUF_B` | `VAND`+`VPERM` table |
| rejUniform vectorized? | No (scalar) | No (scalar) | No (scalar) | No (scalar) |
| Endian correction needed? | No | No | No | Yes (`LXVD2X` reverses 8-byte groups) |
| WORD-encoded instrs | Few | Many | Some | Some |
| Twiddle table shared? | Own | Own | Reuses AVX2 table | Own |
| Requires CPU feature | AVX2 (Haswell 2013+) | NEON (all ARMv8-A) | LASX (LA464 3A5000+) | VMX (POWER8+) |

---

## Performance Summary

Approximate relative throughput (higher is better, normalized to generic Go):

| Operation | Generic | AVX2 | NEON | LASX | VMX |
|-----------|---------|------|------|------|-----|
| NTT Forward | 1× | ~7× | ~4× | ~6× | ~3× |
| NTT Inverse | 1× | ~6× | ~4× | ~5× | ~2.5× |
| polyAddAssign | 1× | ~8× | ~4× | ~8× | ~4× |
| nttMulAcc | 1× | ~6× | ~4× | ~5× | ~2.5× |
| CBD2 sampling | 1× | ~5× | ~3× | ~5× | ~3× |
| CBD3 sampling | 1× | ~5× | ~3× | ~5× | ~3× |
| Compress/decode | 1× | ~4× | ~3× | ~4× | ~2× |

*Note: Actual performance depends on CPU microarchitecture. Measurements should be taken on target hardware using `go test -bench=. ./mlkem/`.*

---

## Files

| File | Purpose |
|------|---------|
| `field.go` | Algorithm core, generic Go implementation, constant definitions |
| `field_asm.go` | Build-tag dispatch to architecture-specific functions |
| `field_noasm.go` | Pure-Go fallback (all architectures with `purego`, or unsupported platforms) |
| `field_amd64.go` | AMD64 function declarations and twiddle table initialization |
| `field_amd64.s` | AMD64 AVX2 assembly (NTT, CBD, compress, rejUniform) |
| `field_arm64.go` | ARM64 function declarations and twiddle table initialization |
| `field_arm64.s` | ARM64 NEON assembly |
| `field_loong64.go` | LoongArch64 function declarations and twiddle table initialization |
| `field_loong64.s` | LoongArch64 LASX assembly |
| `field_ppc64le.go` | ppc64le function declarations and twiddle table initialization |
| `field_ppc64le.s` | ppc64le VMX/AltiVec assembly |
| `field_mont.go` | Montgomery precomputation (used by amd64/arm64/loong64) |
| `mlkem512.go` | ML-KEM-512 public API |
| `mlkem768.go` | ML-KEM-768 public API |
| `mlkem1024.go` | ML-KEM-1024 public API |

---

## Build Tags

```shell
# Default: SIMD assembly enabled (if supported)
go build ./mlkem/

# Pure-Go fallback (no assembly)
go build -tags=purego ./mlkem/

# Cross-compile for target architecture
GOOS=linux GOARCH=ppc64le go build ./mlkem/
GOOS=linux GOARCH=loong64 go build ./mlkem/

# Run benchmarks (on native hardware)
go test -bench=. -benchtime=3s ./mlkem/
```

---

## References

- [NIST FIPS 203](https://csrc.nist.gov/pubs/fips/203/final) — ML-KEM specification
- [Go standard library `crypto/mlkem`](https://pkg.go.dev/crypto/mlkem) — upstream generic implementation
- [OpenSSL ppc64le ML-KEM](https://github.com/openssl/openssl/tree/master/crypto/ml_kem/asm) — Barrett NTT reference for ppc64le
- [CRYSTALS-Kyber reference implementation](https://github.com/pq-crystals/kyber) — original algorithm specification
