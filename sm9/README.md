## SM9 current supported functions:
1.Keys generation  
2.Sign/Verify    
3.Key Exchange  
4.Wrap/Unwrap Key  
5.Encryption/Decryption

## SM9 current performance:

**SM9 Sign/Verify/Enc/Dec Benchmark**

    goos: windows
    goarch: amd64
    pkg: github.com/emmansun/gmsm/sm9
    cpu: Intel(R) Core(TM) i5-8265U CPU @ 1.60GHz
    BenchmarkSign-8          	    3492	    319540 ns/op	   19752 B/op	     545 allocs/op
    BenchmarkVerify-8        	     806	   1475192 ns/op	  161320 B/op	    3894 allocs/op
    BenchmarkEncrypt-8       	    3351	    357549 ns/op	   20971 B/op	     551 allocs/op
    BenchmarkDecrypt-8       	    1052	   1135588 ns/op	  142868 B/op	    3356 allocs/op
    BenchmarkDecryptASN1-8   	    1063	   1129712 ns/op	  142888 B/op	    3358 allocs/op


**SM9 Generate User Sign/Encrypt Private Key Benchmark**

    goos: windows
    goarch: amd64
    pkg: github.com/emmansun/gmsm/sm9
    cpu: Intel(R) Core(TM) i5-8265U CPU @ 1.60GHz
    BenchmarkGenerateSignPrivKey-8      	   18608	     65422 ns/op	     944 B/op	      14 allocs/op
    BenchmarkGenerateEncryptPrivKey-8   	    8486	    151201 ns/op	    1072 B/op	      14 allocs/op

To further improve `Verify()/Decrypt()` performance, need to improve `Pair()` method performance.
