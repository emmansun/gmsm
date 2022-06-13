This part codes mainly refer two projects:

1. [bn256](https://github.com/cloudflare/bn256), 主要是基域运算
2. [gmssl sm9](https://github.com/guanzhi/GmSSL/blob/develop/src/sm9_alg.c)，主要是2-4-12塔式扩域，以及r-ate等


**SM9 Sign Benchmark**

    goos: windows
    goarch: amd64
    pkg: github.com/emmansun/gmsm/sm9
    cpu: Intel(R) Core(TM) i5-9500 CPU @ 3.00GHz
    BenchmarkSign-6   	    1344	    871597 ns/op	   35870 B/op	    1013 allocs/op


**SM9 Verify Benchmark**

    goos: windows
    goarch: amd64
    pkg: github.com/emmansun/gmsm/sm9
    cpu: Intel(R) Core(TM) i5-9500 CPU @ 3.00GHz
    BenchmarkVerify-6   	     352	   3331673 ns/op	  237676 B/op	    6283 allocs/op

**SM9 Encrypt(XOR) Benchmark**

    goos: windows
    goarch: amd64
    pkg: github.com/emmansun/gmsm/sm9
    cpu: Intel(R) Core(TM) i5-9500 CPU @ 3.00GHz
    BenchmarkEncrypt-6   	    1120	    971188 ns/op	   38125 B/op	    1036 allocs/op

**SM9 Decrypt(XOR) Benchmark**

    goos: windows
    goarch: amd64
    pkg: github.com/emmansun/gmsm/sm9
    cpu: Intel(R) Core(TM) i5-9500 CPU @ 3.00GHz
    BenchmarkDecrypt-6   	     507	   2345492 ns/op	  202360 B/op	    5228 allocs/op

To further improve `Verify()/Decrypt()` performance, need to improve `Pair()` method performance.
