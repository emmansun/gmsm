# GMSM - Chinese ShangMi (商密) Cryptographic Library

GMSM is a high-performance Go cryptographic library implementing Chinese National Standards (GB/T) for SM2, SM3, SM4, SM9, and ZUC algorithms, plus NIST Post-Quantum Cryptography (ML-KEM, ML-DSA, SLH-DSA), with extensive SIMD optimizations across multiple architectures. Requires **Go 1.24+**.

## Architecture Overview

### Module Organization
- **`internal/`**: Core algorithm implementations with architecture-specific optimizations
  - `internal/sm2/`, `internal/sm2ec/`: SM2 elliptic curve operations (similar to NIST P-256)
  - `internal/sm3/`, `internal/sm4/`, `internal/sm9/`, `internal/zuc/`: Hash and cipher primitives
  - `internal/entropy/`: Multi-source entropy collection with SP 800-90B health testing for `rand/`
  - `internal/deps/cpu/`: Vendored Go `internal/cpu` for feature detection (AVX2, NEON, etc.)
  - `internal/cpuid/`: Lightweight AES-NI/GFMUL detection for SM4/ZUC
  - Assembly files (`.s`) provide SIMD implementations for amd64, arm64, ppc64x, s390x, riscv64, loong64
- **Public packages**: User-facing APIs mimicking Go's crypto standard library patterns
  - `sm2/`, `sm3/`, `sm4/`, `sm9/`, `zuc/`: Direct algorithm interfaces
  - `smx509/`: Fork of Go's x509 with SM2/SM3 + ML-DSA/SLH-DSA certificate support
  - `pkcs7/`, `pkcs8/`: PKCS standards with SM + PQC extensions
  - `cipher/`: Extended block cipher modes (ECB, XTS, HCTR, CCM, BC, OFBNLF)
  - `padding/`: GB/T 17964-2021 compliant padding schemes with constant-time unpadding
  - `cfca/`: CFCA (China Financial CA) interoperability layer
- **Post-Quantum Cryptography packages**:
  - `mlkem/`: ML-KEM (FIPS 203) — key encapsulation (512/768/1024), AVX2 + NEON assembly
  - `mldsa/`: ML-DSA (FIPS 204) — digital signatures (44/65/87), AVX2 + NEON assembly
  - `slhdsa/`: SLH-DSA (FIPS 205) — stateless hash-based signatures (12 standard + 2 SM3 parameter sets)
  - `tls13/`: TLS 1.3 hybrid key exchange (ECDH + ML-KEM), including SM2MLKEM768 extension
- **Supporting packages**:
  - `drbg/`: Deterministic Random Bit Generators (CTR/Hash/HMAC DRBG, NIST & GM/T modes)
  - `rand/`: GM/T 0105-2021 compliant random number generator (SM3 Hash DRBG + multi-source entropy)
  - `ecdh/`: SM2 ECDH / SM2-MQV key exchange
  - `kdf/`: SM2 key derivation function
  - `shake/`: hash.Hash adapters for SHAKE128/SHAKE256 XOFs

### Build Tags and Optimization Strategy
- **Assembly dispatch**: Code uses build tags like `//go:build (amd64 || arm64) && !purego`
- **purego**: All algorithms have pure Go fallbacks; set `purego` tag to disable assembly
- **CPU feature detection**: `internal/deps/cpu` for AVX2/NEON detection (mlkem, mldsa, bn256); `internal/cpuid` for AES-NI/GFMUL (sm4, zuc)
- **Mode-specific optimization**: SM4 ECB/CBC/GCM/XTS have fused cipher+mode implementations in `internal/sm4/`
- **PQC assembly**: ML-KEM and ML-DSA have NTT/encoder assembly for both amd64 (AVX2) and arm64 (NEON)

## Key Development Patterns

### Testing Conventions
- **`*_test.go`**: Standard test files with `TestXxx`, `BenchmarkXxx`, and `ExampleXxx` functions
- **Benchmark naming**: Use descriptive sizes like `BenchmarkHash1K`, `BenchmarkHash8K`
- **Test data**: Often embedded as hex strings or structured test vectors from national standards
- **Example tests**: Extensive `Example*` functions demonstrate API usage (see `sm4/example_test.go`, `zuc/example_test.go`)

### Cipher Interface Implementation
All symmetric ciphers implement Go's `cipher.Block` interface. Enhanced modes use adapter interfaces:
```go
// Pattern for optimized modes (from cipher/ecb.go)
type ecbEncAble interface {
    NewECBEncrypter() cipher.BlockMode
}
// SM4 implements this to return optimized path
```

### OID Registration Pattern (PKCS)
The `pkcs/` package uses init-time registration for algorithm identifiers:
```go
// Pattern from pkcs/cipher_sm4.go
var oidSM4CBC = asn1.ObjectIdentifier{1, 2, 156, 10197, 1, 104, 2}

func init() {
    RegisterCipher(oidSM4CBC, func() Cipher { return SM4CBC })
}
```

### Assembly File Organization
Assembly implementations follow naming: `<feature>_<arch>.s` or `<feature>_asm_<arch>.s`. Example:
- `internal/sm4/gcm_amd64.s`, `internal/zuc/eia_asm_arm64.s`
- `mldsa/field_amd64.s`, `mlkem/field_arm64.s` (PQC NTT assembly)
- Pure Go versions: `<feature>_generic.go` with build tag `//go:build purego || !(amd64 || ...)`

## Security Patterns

### Constant-Time Operations
- **Padding removal**: All padding schemes in `padding/` provide `ConstantTimeUnpad()` to prevent timing attacks
- **ECDH/Key Exchange**: SM2 key exchange in `ecdh/` and `internal/sm2/` avoids `big.Int` for constant-time guarantees
- **ML-KEM**: Implicit rejection on decapsulation failure (constant-time comparison)
- **DRBG**: `zeroize` uses `clear(data) + runtime.KeepAlive(data)` to prevent dead-store elimination
- Refer to Wiki: ["is my code constant time?"](https://github.com/emmansun/gmsm/wiki/is-my-code-constant-time%3F)

### Deprecated Algorithms
- **DES/3DES** (`pkcs/cipher_des.go`): Marked with warnings, provided only for backward compatibility
- **ECB mode**: Discouraged; comments warn against standalone use
- **BC/OFBNLF modes** (`cipher/bc.go`, `cipher/ofbnlf.go`): Legacy GB/T 17964 modes, not recommended for new applications

## Common Workflows

### Running Tests
```powershell
# Test specific package
go test -v ./sm4/

# Run benchmarks with specific size
go test -bench=BenchmarkHash1K -benchtime=3s ./sm3/

# Test with purego (no assembly)
go test -tags=purego ./...
```

### Adding New Algorithm Support
1. Create pure Go implementation in `internal/<alg>/` with `_generic.go` suffix
2. Add optimized assembly in `internal/<alg>/<feature>_<arch>.s`
3. Create public API in top-level package following Go crypto patterns
4. Add comprehensive test vectors from national standards
5. Provide usage examples in `example_test.go`

### X.509 Certificate Handling
Use `smx509/` (not `crypto/x509`) for SM2 and PQC certificates:
```go
import "github.com/emmansun/gmsm/smx509"
// Parse, verify, create certificates with SM2/SM3 + ML-DSA/SLH-DSA support
```

## Documentation Structure

Each major algorithm has a user guide in `docs/`:
- `docs/sm2.md`: Key generation, signatures, encryption, key exchange
- `docs/sm4.md`: Block cipher modes, padding, performance notes
- `docs/sm3.md`, `docs/sm9.md`, `docs/zuc.md`: Algorithm-specific guidance
- `docs/pqc.md`: ML-KEM, ML-DSA, SLH-DSA and TLS 1.3 hybrid-KEM usage
- `docs/cfca.md`, `docs/pkcs7.md`, `docs/pkcs12.md`: Interoperability guides
- `docs/rand.md`: GM/T 0105-2021 compliant random number generator

## Integration Notes

### CFCA Compatibility
The `cfca/` package provides drop-in replacements for CFCA SADK methods:
- `SignMessageAttach` ↔ `cfca.sadk.util.p7SignMessageAttach`
- `VerifyMessageDetach` ↔ `cfca.sadk.util.p7VerifyMessageDetach`
- See `cfca/pkcs7_sign.go` for mapping

### Standard Compliance
- **GB/T 17964-2021**: Block cipher modes (XTS supports both GB/T and NIST SP 800-38E)
- **GB/T 15852.1-2020**: MAC algorithms (CBCMAC package implements 8 schemes)
- **GM/T standards**: ZUC (GM/T 0001-2012), SM2/3/4/9 specifications
- **GM/T 0105-2021**: Random number generator (`rand/` package)
- **NIST FIPS**: MLKEM (203), MLDSA (204), SLHDSA (205) for post-quantum

## Performance Considerations

- **Mode-specific implementations**: Prefer optimized constructors (e.g., `cipher.NewECBEncrypter` over manual block iteration)
- **XTS mode**: NOT concurrent-safe due to internal tweak state
- **GCM over CBC**: Recommended for authenticated encryption unless interoperability requires CBC
- **Batch operations**: Use `CryptBlocks` methods for bulk data processing
- **SM9 pairing**: Use `G2.Precompute()` + `PairPrecomp()` when G2 point is fixed (e.g., private keys)
- **GT scalar multiplication**: Uses 4-bit window with cyclotomic squaring (`ScalarMultGT`)

## Related Projects
- **TLCP**: GB/T 38636-2020 Transport Layer Cryptography Protocol (github.com/Trisia/gotlcp)
- **Randomness testing**: GM/T 0005-2021 compliance tool (github.com/Trisia/randomness)
