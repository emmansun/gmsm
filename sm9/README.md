## SM9 current supported functions:
1.Keys generation  
2.Sign/Verify    
3.Key Exchange  
4.Wrap/Unwrap Key  
5.Encryption/Decryption

## SM9 current performance:

**SM9 Sign Benchmark**

    goos: windows
    goarch: amd64
    pkg: github.com/emmansun/gmsm/sm9
    cpu: Intel(R) Core(TM) i5-9500 CPU @ 3.00GHz
    BenchmarkSign-6   	    1344	    871597 ns/op	   35870 B/op	    1013 allocs/op

    优化后(减少乘法、优化Invert)性能：
    goos: windows
    goarch: amd64
    pkg: github.com/emmansun/gmsm/sm9
    cpu: Intel(R) Core(TM) i5-8265U CPU @ 1.60GHz
    BenchmarkSign-8   	    2841	    392368 ns/op	   19845 B/op	     545 allocs/op

**SM9 Verify Benchmark**

    goos: windows
    goarch: amd64
    pkg: github.com/emmansun/gmsm/sm9
    cpu: Intel(R) Core(TM) i5-9500 CPU @ 3.00GHz
    BenchmarkVerify-6   	     352	   3331673 ns/op	  237676 B/op	    6283 allocs/op

    优化后(减少乘法、优化Invert)性能：
    goos: windows
    goarch: amd64
    pkg: github.com/emmansun/gmsm/sm9
    cpu: Intel(R) Core(TM) i5-8265U CPU @ 1.60GHz
    BenchmarkVerify-8   	     709	   1710580 ns/op	  179686 B/op	    4370 allocs/op

**SM9 Encrypt(XOR) Benchmark**

    goos: windows
    goarch: amd64
    pkg: github.com/emmansun/gmsm/sm9
    cpu: Intel(R) Core(TM) i5-9500 CPU @ 3.00GHz
    BenchmarkEncrypt-6   	    1120	    971188 ns/op	   38125 B/op	    1036 allocs/op

    优化后(减少乘法、优化Invert)性能：
    goos: windows
    goarch: amd64
    pkg: github.com/emmansun/gmsm/sm9
    cpu: Intel(R) Core(TM) i5-8265U CPU @ 1.60GHz
    BenchmarkEncrypt-8   	    2551	    440724 ns/op	   21149 B/op	     553 allocs/op

**SM9 Decrypt(XOR) Benchmark**

    goos: windows
    goarch: amd64
    pkg: github.com/emmansun/gmsm/sm9
    cpu: Intel(R) Core(TM) i5-9500 CPU @ 3.00GHz
    BenchmarkDecrypt-6   	     507	   2345492 ns/op	  202360 B/op	    5228 allocs/op

    优化后(减少乘法、优化Invert)性能：
    goos: windows
    goarch: amd64
    pkg: github.com/emmansun/gmsm/sm9
    cpu: Intel(R) Core(TM) i5-8265U CPU @ 1.60GHz
    BenchmarkDecrypt-8   	     925	   1310317 ns/op	  159924 B/op	    3811 allocs/op

**SM9 Generate User Sign Private Key Benchmark**

    goos: windows
    goarch: amd64
    pkg: github.com/emmansun/gmsm/sm9
    cpu: Intel(R) Core(TM) i5-9500 CPU @ 3.00GHz
    BenchmarkGenerateSignPrivKey-6   	    8078	    147638 ns/op	    3176 B/op	      47 allocs/op

**SM9 Generate User Encrypt Private Key Benchmark**

    goos: windows
    goarch: amd64
    pkg: github.com/emmansun/gmsm/sm9
    cpu: Intel(R) Core(TM) i5-9500 CPU @ 3.00GHz
    BenchmarkGenerateEncryptPrivKey-6   	    3445	    326796 ns/op	    3433 B/op	      47 allocs/op

To further improve `Verify()/Decrypt()` performance, need to improve `Pair()` method performance.
