
# GM-Standards SM2/SM3/SM4/SM9/ZUC for Go

[![Travis CI](https://app.travis-ci.com/emmansun/gmsm.svg?branch=main)](https://app.travis-ci.com/emmansun/gmsm) 
[![Github CI](https://github.com/emmansun/gmsm/actions/workflows/ci.yml/badge.svg)](https://github.com/emmansun/gmsm/actions/workflows/ci.yml) 
[![codecov](https://codecov.io/gh/emmansun/gmsm/branch/main/graph/badge.svg?token=Otdi8m8sFj)](https://codecov.io/gh/emmansun/gmsm)
[![Go Report Card](https://goreportcard.com/badge/github.com/emmansun/gmsm)](https://goreportcard.com/report/github.com/emmansun/gmsm)
[![Documentation](https://godoc.org/github.com/emmansun/gmsm?status.svg)](https://godoc.org/github.com/emmansun/gmsm) 
[![Release](https://img.shields.io/github/release/emmansun/gmsm/all.svg)](https://github.com/emmansun/gmsm/releases)

This is a **SM2 sm2p256v1** implementation whose performance is similar like golang native NIST P256 under **amd64** and **arm64**, for implementation detail, please refer [SM2实现细节](https://github.com/emmansun/gmsm/wiki/SM2%E6%80%A7%E8%83%BD%E4%BC%98%E5%8C%96).

This is also a **SM3** implementation whose performance is similar like golang native SHA 256 with SIMD under **amd64**, for implementation detail, please refer [SM3性能优化](https://github.com/emmansun/gmsm/wiki/SM3%E6%80%A7%E8%83%BD%E4%BC%98%E5%8C%96).

For **SM4** implementation, SIMD & AES-NI are used under **amd64** and **arm64**, for detail please refer [SM4性能优化](https://github.com/emmansun/gmsm/wiki/SM4%E6%80%A7%E8%83%BD%E4%BC%98%E5%8C%96), support CBC/CFB/OFB/CTR/GCM/CCM/XTS modes.

**SM2 encryption Benchmark**

    CPU: i5-9500
    P-256/SM2(No tuning)
    goos: windows
    goarch: amd64
    pkg: gmsm/sm2
    BenchmarkLessThan32-6   	     210	   5665861 ns/op	   0.01 MB/s	 2601864 B/op	   27725 allocs/op
    PASS
    ok  	gmsm/sm2	5.629s
    
    P-256/SM2(with P256/SM2 curve pure golang implementation)
    goos: windows
    goarch: amd64
    pkg: gmsm/sm2
    BenchmarkLessThan32_P256SM2-6   	    1027	   1169516 ns/op	    3874 B/op	      74 allocs/op
    PASS
    ok  	gmsm/sm2	1.564s

    P-256/SM2(with P256/SM2 amd64 curve implementation, i think there are still improvement space for p256Sqr function)
    goos: windows
    goarch: amd64
    pkg: github.com/emmansun/gmsm/sm2
    BenchmarkLessThan32_P256SM2-6   	   10447	    115618 ns/op	    2357 B/op	      46 allocs/op
    PASS
    ok  	github.com/emmansun/gmsm/sm2	2.199s

    P-256 (SM2 based on NIST P-256 curve)
    goos: windows
    goarch: amd64
    pkg: gmsm/sm2
    BenchmarkMoreThan32-6   	   13656	     86252 ns/op	    3141 B/op	      50 allocs/op
    PASS
    ok  	gmsm/sm2	4.139s

**SM3 hash Benchmark**

    CPU: i5-9500
    Pure golang version
    goos: windows
    goarch: amd64
    pkg: github.com/emmansun/gmsm/sm3
    BenchmarkHash8K-6   	   27097	     41112 ns/op	 199.26 MB/s	       0 B/op	       0 allocs/op
    PASS
    ok  	github.com/emmansun/gmsm/sm3	3.463s

    ASM (non-AVX2) version
    goos: windows
    goarch: amd64
    pkg: github.com/emmansun/gmsm/sm3
    BenchmarkHash8K-6   	   35080	     33235 ns/op	 246.49 MB/s	       0 B/op	       0 allocs/op
    PASS
    ok  	github.com/emmansun/gmsm/sm3	3.102s

    ASM AVX2 version
    goos: windows
    goarch: amd64
    pkg: github.com/emmansun/gmsm/sm3
    BenchmarkHash8K-6   	   53208	     22223 ns/op	 368.63 MB/s	       0 B/op	       0 allocs/op
    PASS
    ok  	github.com/emmansun/gmsm/sm3	1.720s 

    SHA256 ASM AVX2 version
    goos: windows
    goarch: amd64
    pkg: github.com/emmansun/gmsm/sm3
    BenchmarkHash8K_SH256-6   	   68352	     17116 ns/op	 478.63 MB/s	       0 B/op	       0 allocs/op
    PASS
    ok  	github.com/emmansun/gmsm/sm3	3.043s    

**SM4 Benchmark**

    CPU: i5-9500
    Pure golang version
    goos: windows
    goarch: amd64
    pkg: github.com/emmansun/gmsm/sm4
    BenchmarkEncrypt-6   	 2671431	       441 ns/op	  36.28 MB/s	       0 B/op	       0 allocs/op
    BenchmarkDecrypt-6   	 2709132	       440 ns/op	  36.40 MB/s	       0 B/op	       0 allocs/op
    BenchmarkExpand-6    	 2543746	       471 ns/op	      16 B/op	       1 allocs/op
    
    ASM AES-NI version
    goos: windows
    goarch: amd64
    pkg: github.com/emmansun/gmsm/sm4
    BenchmarkEncrypt-6   	 5881989	       206 ns/op	  77.75 MB/s	       0 B/op	       0 allocs/op
    BenchmarkDecrypt-6   	 5853994	       204 ns/op	  78.45 MB/s	       0 B/op	       0 allocs/op
    BenchmarkExpand-6    	 5985129	       200 ns/op	       0 B/op	       0 allocs/op
    PASS
    ok  	github.com/emmansun/gmsm/sm4	6.193s
