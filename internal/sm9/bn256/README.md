# BN256 for SM9 — Implementation Notes and Optimizations

This package implements the BN256 bilinear pairing for the SM9 identity-based cryptographic algorithm (GB/T 38635).

## Origins

The code draws from two primary sources:

1. **[cloudflare/bn256](https://github.com/cloudflare/bn256)** — base field arithmetic.  
   Issues in the original: sparse test coverage, many missed optimizations. Improvements made: more tests, fewer multiplications, constant-time `ScalarMult`, optimized `Invert`/`Sqrt`, eventually a replacement base-field implementation.

2. **[GmSSL sm9](https://github.com/guanzhi/GmSSL/blob/develop/src/sm9_alg.c)** — 2-4-12 tower field (this package implements both 1-2-4-12 and 1-2-6-12 towers with inter-conversion), and the R-ate pairing.  
   Issues in the original: no performance optimization. The R-ate Miller loop was later reworked against cloudflare's optimal-ate approach, adapted to SM9's specific curve parameters.

---

## Curve Parameters

SM9 uses a **Barreto-Naehrig (BN) curve** with parameter:

```
u = 0x600000000058F98A   (63-bit, positive)
p = 36u⁴ + 36u³ + 24u² + 6u + 1    (256-bit prime)
r = 36u⁴ + 36u³ + 18u² + 6u + 1    (256-bit prime, group order)
```

The pairing is computed over:
- **G1** = E(Fp) — points on the base curve
- **G2** = E'(Fp²) — points on the twisted curve (degree-6 twist)
- **GT** = μᵣ ⊂ Fp¹² — the r-th roots of unity in the degree-12 extension

---

## Field Tower Structure

Two equivalent towers are implemented:

| Tower | Files | Structure |
|-------|-------|-----------|
| 1-2-4-12 | `gfp.go`, `gfp2.go`, `gfp4.go`, `gfp12.go` | Fp → Fp² → Fp⁴ → Fp¹² |
| 1-2-6-12 | `gfp2.go`, `gfp6.go`, `gfp12b6.go` | Fp → Fp² → Fp⁶ → Fp¹² |

Benchmarks show both towers have essentially the same performance (~140 µs for `finalExponentiation`). The 1-2-4-12 tower (`gfP12`) is the primary implementation. The 1-2-6-12 tower (`gfP12b6`) is maintained for comparison and as an alternative.

---

## Optimizations

### 1. Base Field Assembly (gfP)

**Files:** `gfp_amd64.s`, `gfp_arm64.s`, `gfp_loong64.s`, `gfp_ppc64x.s`, `gfp_riscv64.s`

Montgomery multiplication and squaring for the 256-bit prime field are implemented in architecture-specific assembly. This provides the foundation for all higher-level operations.

**Impact:** Removing assembly (via `-tags=purego`) slows `gfP12.Mul` by 3.25× and `Cyclo6Square` by 3.69×.

### 2. Fp² Assembly (gfP2)

**Files:** `gfp2_g1_amd64.s`, `gfp2_g1_arm64.s`

The five core Fp² operations have dedicated assembly implementations:
- `gfp2Mul(a, b, c *gfP2)` — multiplication using Karatsuba
- `gfp2MulU(a, b, c *gfP2)` — multiplication by the twist coefficient `u`
- `gfp2MulU1(a, b *gfP2)` — multiplication by `u` (one argument)
- `gfp2Square(a, b *gfP2)` — squaring
- `gfp2SquareU(a, b *gfP2)` — squaring for twist-coefficient variant

All Fp⁴, Fp⁶, and Fp¹² operations are built on top of these Fp² primitives. No dedicated assembly exists above Fp²; the Go compiler handles the higher tower levels.

### 3. Cyclotomic Subgroup Squaring (Cyclo6Square)

**File:** `gfp12.go` — `Cyclo6Square`, `Cyclo6SquareNC`, `Cyclo6Squares`

**Reference:** Granger, R. and Scott, M., "Faster Squaring in the Cyclotomic Subgroup of Sixth Degree Extensions," PKC 2010. [[eprint 2009/565]](https://eprint.iacr.org/2009/565)

GT elements (output of the pairing's final exponentiation) lie in the **cyclotomic subgroup** of Fp¹². In this subgroup, squaring can be computed with 3 Fp² squarings instead of 6 (for the general case), using the Granger-Scott formula:

For `f = (a, b, c)` in Fp¹² = Fp⁴[w]/(w³ - ξ), the cyclotomic square satisfies a special structure that allows reuse of intermediate values.

**Performance:** `Cyclo6Square` = 472 ns vs general `Square` = 819 ns (1.74× faster). All doublings in GT scalar multiplication and the final exponentiation hard part use `Cyclo6Square`.

### 4. Optimal Ate Pairing / Miller Loop

**File:** `bn_pair.go` — `miller`, `lineFunctionDouble`, `lineFunctionAdd`

**Reference:** Vercauteren, F., "Optimal Pairings," IEEE Transactions on Information Theory, 2010. [[eprint 2008/096]](https://eprint.iacr.org/2008/096)

For BN curves, the optimal ate pairing uses the Miller loop with the integer `6u + 2` expressed in non-adjacent form (NAF):

```
sixUPlus2NAF = NAF(6·u + 2)    (66 entries for u = 0x600000000058F98A)
```

The loop runs for 65 iterations (i = 65 down to 1), with:
- 65 line-function doublings
- 10 line-function additions (at NAF non-zero positions)
- 2 post-loop Frobenius additions (for the `+2` correction)

Total: **77 line evaluations** per Miller loop invocation.

This is the **theoretical minimum** Miller loop length for this BN256 curve. No shorter loop is achievable without changing the curve.

**Note on line functions:** `lineFunctionDouble` and `lineFunctionAdd` operate on stack-allocated `gfP2` intermediates (verified by Go escape analysis: `BenchmarkMiller` shows 1 alloc/op = 384 bytes = only the gfP12 return value).

### 5. G2 Precomputed Pairing

**File:** `g2_precomp.go` — `G2Precomputed`, `PrecomputeG2`, `PairPrecomp`

**Reference:** Beuchat, J.L. et al., "High-Speed Software Implementation of the Optimal Ate Pairing over Barreto-Naehrig Curves," Pairing 2010. [[eprint 2010/354]](https://eprint.iacr.org/2010/354) (Section 4 on precomputation)

When the G2 point (e.g., a user's SM9 private key) is **fixed**, all G2 arithmetic can be precomputed. The `G2Precomputed` type stores 77 line evaluation tuples `(a, b, c)` where `b` and `c` exclude the G1 scaling factors.

**Algorithm:**
- **Precomputation** (`PrecomputeG2`): Run the standard G2 doubling/addition steps once, storing `b_coeff = -2·E·r.t` and `c_coeff = 2·rOut.z·r.t` for each doubling, and `b_coeff = -2·L₁` and `c_coeff = 2·rOut.z` for each addition.
- **Online** (`millerWithPrecomp`): For each of the 77 line evaluations, compute `b_final = b_coeff · P.x` and `c_final = c_coeff · P.y` (two Fp² scalings) then call `mulLine`. All G2 point arithmetic is eliminated.

**Storage:** `G2Precomputed` = 77 × 3 gfP2 = 77 × 3 × 64 bytes = **14,784 bytes** (one allocation).

**Performance (Intel i7-13700):**

| Operation | Before | After | Speedup |
|-----------|--------|-------|---------|
| `BenchmarkMiller` | 158,340 ns | 115,918 ns | **-27%** |
| `BenchmarkPairing` (full) | 300,079 ns | 254,992 ns | **-15%** |
| `PrecomputeG2` | — | 46,131 ns | one-time cost |

**Usage in SM9:** Applied to:
- `EncryptMasterPublicKey.pair()` — uses `gen2Precomp` (package-level precomputed Gen2)
- `EncryptPrivateKey` — lazy-initializes precomputed form of the G2 private key on first use via `getPrecomp()` + `sync.Once`
- Key exchange: `respondKeyExchange`, `ConfirmResponder`

### 6. Final Exponentiation

**File:** `bn_pair.go` — `finalExponentiation`

**References:**
- Fuentes-Castañeda, L. et al., "Faster Hashing to G2," SAC 2011 / Optimal Final Exp. [[eprint 2010/354]](https://eprint.iacr.org/2010/354)
- Beuchat, J.L. et al., "High-Speed Software Implementation of the Optimal Ate Pairing over Barreto-Naehrig Curves," Pairing 2010. [[eprint 2010/354]](https://eprint.iacr.org/2010/354)

The final exponentiation computes the `(p¹²−1)/r`-th power, which factors as:

$$\frac{p^{12}-1}{r} = (p^6-1)(p^2+1) \cdot \frac{p^4-p^2+1}{r}$$

**Easy part:** `(p⁶−1)(p²+1)`
```
t1 = FrobeniusP6(in) · in⁻¹   // in^(p^6 - 1), FrobeniusP6 = Conjugate
t1 = FrobeniusP2(t1) · t1      // t1^(p^2 + 1)
```
After this, `t1` lies in the cyclotomic subgroup.

**Hard part:** `(p⁴−p²+1)/r` using the Fuentes-Castañeda algorithm:
```
fu  = Cyclo6PowToU(t1)     // t1^u
fu2 = Cyclo6PowToU(fu)     // t1^(u²)
fu3 = Cyclo6PowToU(fu2)    // t1^(u³)
```
Then: compute `y0 = fp·fp2·fp3`, `y1..y6` via Frobenius and Conjugate operations, and combine with the final chain using `Cyclo6Square` and `Mul`.

**Cost breakdown (Intel i7-13700):**

| Component | Cost | Share |
|-----------|------|-------|
| 3× `Cyclo6PowToU` | ~114,000 ns | **81%** |
| Easy part (Invert + 2 Mul + Frobenius) | ~14,000 ns | 10% |
| Final chain (Mul + Cyclo6Square combinations) | ~12,000 ns | 9% |
| **Total** | **~140,733 ns** | — |

### 7. Cyclo6PowToU — Addition Chain for u

**File:** `gfp12_exp_u.go` — `Cyclo6PowToU`

**Tool:** Generated with [addchain v0.4.0](https://github.com/mmcloughlin/addchain) for `u = 0x600000000058F98A`.

The optimal addition chain for `u` uses **10 multiplications and 61 cyclotomic squarings** (vs ~63 muls + ~61 sq for the binary method):

```
_10    = 2·1
_100   = 2·_10
_101   = 1 + _100
_1001  = _100 + _101
_1011  = _10 + _1001
_1100  = 1 + _1011
i56    = (_1100 << 40 + _1011) << 7 + _1011 + _100
i69    = (2·(i56 << 4 + _1001) + 1) << 6
return   2·(_101 + i69)
```

All squarings use `Cyclo6Square` (cyclotomic squaring). All multiplications are general `gfP12.Mul`.

### 8. GT Scalar Multiplication — 4-bit Window + Cyclo6Squares

**Files:** `gt.go` — `ScalarMultGT`, `ScalarBaseMultGT`, `GT.ScalarMult`, `GT.ScalarBaseMult`

**Reference:** Standard sliding-window scalar multiplication adapted for cyclotomic elements.

For a 256-bit scalar `k` and GT element `a` (in the cyclotomic subgroup), the 4-bit window method:

1. Build a 15-element table: `table[i] = a^(i+1)` using `Cyclo6SquareNC` for doublings and `GT.Add` (= Fp¹² multiplication) for odd entries.
2. Process the scalar 4 bits at a time: for each nibble `w`, compute `e = e^(2⁴) · table[w]` where `e^(2⁴)` uses `Cyclo6Squares(e, 4)`.

`GT.ScalarMult(a, k *big.Int)` delegates to `ScalarMultGT(a, NormalizeScalar(k.Bytes()))`, gaining the benefit of Cyclo6Square-based doublings. Previously it used `gfP12.Exp` (binary square-and-multiply with general `Square`), which was ~3× slower.

`ScalarBaseMultGT` uses a **precomputed two-table structure** (`[32×2]GTFieldTable`) that precomputes `a^(2^(4k))` for all window positions, enabling an additive-only loop (no doublings at runtime):

```
table[i] stores [16]GT entries for window position i,
with table[i][j] = a^(j · 2^(4i))
```

This is the fully precomputed analogue — used when the base point is fixed (e.g., `e(Gen1, Ppub)` for signature verification).

### 9. G1 and G2 Point Precomputation

**File:** `g1.go` — `ScalarBaseMult`, `generatorTable()`  
**File:** `g2.go` — implied (G2 scalar mult uses similar patterns)

Fixed-base scalar multiplication for G1 uses a precomputed window table over the generator point. The table is computed once (lazily via `sync.Once`) and reused across all calls.

### 10. Constant-Time Operations

- `G1.ScalarMult`, `G2.ScalarMult` use constant-time select via `select_amd64.s` / `select_arm64.s` / `select_ppc64x.s`
- `GTFieldTable.Select` uses `subtle.ConstantTimeByteEq` + `gfP12MovCond` (implemented in assembly where available)
- All timing-sensitive operations avoid data-dependent branches over secret values

---

## Performance Summary (Intel Core i7-13700)

All values from `go test ./internal/sm9/bn256/ -bench=... -benchtime=3s`.

| Operation | Time | Notes |
|-----------|------|-------|
| `gfP12.Mul` | 1,086 ns | |
| `gfP12.Square` (general) | 820 ns | |
| `gfP12.Cyclo6Square` | 455 ns | ~1.8× faster than general Square |
| `gfP12.Invert` | 6,101 ns | |
| `Cyclo6PowToU` (×1) | ~38,132 ns | 1/3 of `BenchmarkGfP12ExpU` (3×) |
| Miller loop (no precomp) | 158,340 ns | `BenchmarkMiller` |
| Miller loop (G2 precomp) | 115,918 ns | `BenchmarkMillerWithPrecomp` (-27%) |
| Final exponentiation | 140,733 ns | `BenchmarkFinalExponentiation` |
| Full pairing `e(P,Q)` | 300,079 ns | `BenchmarkPairing` |
| Full pairing (G2 precomp) | 254,992 ns | `BenchmarkPairPrecomp` (-15%) |
| `GT.ScalarMult` (256-bit, 4-bit window) | 203,264 ns | `BenchmarkGT`; ~1.7× vs old binary Exp |
| `PrecomputeG2` | 46,131 ns | one-time cost per fixed G2 point |

**Effect of assembly (`-tags=purego` disables gfP2 asm):**

| Operation | With asm | Pure Go | Assembly speedup |
|-----------|----------|---------|-----------------|
| `gfP12.Mul` | 1,086 ns | 3,517 ns | **3.24×** |
| `gfP12.Square` | 820 ns | 2,876 ns | **3.51×** |
| `gfP12.Cyclo6Square` | 455 ns | 1,666 ns | **3.66×** |

---

## Remaining Optimization Opportunities

### gfP4 / gfP12 Assembly (est. +10–15% on finalExponentiation)

Currently only Fp and Fp² have assembly. Implementing `gfP4.Mul` in assembly would:
- Eliminate per-multiplication Go function call overhead
- Keep intermediates in registers across Karatsuba steps
- Estimated gain: ~10–15% for `finalExponentiation`, ~10% for overall pairing

This is a significant undertaking — the existing Fp² assembly is already ~1,900 lines; Fp⁴ would be comparable.

### Batch / Multi-Pairing (amortize finalExponentiation)

For workloads requiring N pairings simultaneously (e.g., batch signature verification):

$$\prod_{i=1}^{N} e(P_i, Q_i) \stackrel{?}{=} T$$

Merge all N Miller loops (each producing one Fp¹² element), multiply the N Miller results, and apply `finalExponentiation` **once**. This saves (N−1) × ~140,000 ns = (N−1) × 14% of the full pairing time per additional pair.

SM9's single-signature verify computes only 1 pairing, so this requires an API-level batch-verify function.

### Alternative Hard Part (est. <5% on finalExponentiation)

The Fuentes-Castañeda hard part (current) uses 3 sequential `Cyclo6PowToU` calls. Alternative methods (Scott 2009 [[eprint 2009/615]](https://eprint.iacr.org/2009/615), Arene et al. 2010 [[eprint 2010/354]](https://eprint.iacr.org/2010/354)) use similar structures — all require computing `t1^u`, `t1^(u²)`, `t1^(u³)`. The 3 `PowToU` calls are **fundamental to BN curves** and cannot be reduced below this count.

---

## References

1. Barreto, P.S.L.M. and Naehrig, M., "Pairing-Friendly Elliptic Curves of Prime Order," SAC 2005. [[eprint 2005/133]](https://eprint.iacr.org/2005/133)
2. Vercauteren, F., "Optimal Pairings," IEEE Transactions on Information Theory, 2010. [[eprint 2008/096]](https://eprint.iacr.org/2008/096)
3. Granger, R. and Scott, M., "Faster Squaring in the Cyclotomic Subgroup of Sixth Degree Extensions," PKC 2010. [[eprint 2009/565]](https://eprint.iacr.org/2009/565)
4. Beuchat, J.L. et al., "High-Speed Software Implementation of the Optimal Ate Pairing over Barreto-Naehrig Curves," Pairing 2010. [[eprint 2010/354]](https://eprint.iacr.org/2010/354)
5. Fuentes-Castañeda, L. et al., "Faster Hashing to G2," SAC 2011. [[eprint 2011/169]](https://eprint.iacr.org/2011/169)
6. Scott, M., "On the Efficient Implementation of Pairing-Based Protocols," EUROCRYPT 2011. [[eprint 2009/615]](https://eprint.iacr.org/2009/615)
7. McLoughlin, M., "Addchain: Addition Chain Generation for Cryptographic Computation." [[github]](https://github.com/mmcloughlin/addchain)
8. GB/T 38635.1-2020, "Information security technology — SM9 identity cryptography algorithm."
