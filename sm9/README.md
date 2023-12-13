## SM9 current supported functions:
* Keys generation（密钥生成）  
* Sign/Verify （数字签名算法）   
* Key Exchange （密钥交换协议）  
* Wrap/Unwrap Key （密钥封装机制）  
* Encryption/Decryption （公钥加密算法）

## Reference
* Information security technology—Identity-based cryptographic algorithms SM9—Part 1：General《GB/T 38635.1-2020  信息安全技术 SM9标识密码算法 第1部分：总则》
* Information security technology—Identity-based cryptographic algorithms SM9—Part 2：Algorithms《GB/T 38635.2-2020 信息安全技术 SM9标识密码算法 第2部分：算法》
* Information security technology—SM9 cryptographic algorithm application specification《GB/T 41389-2022 信息安全技术 SM9密码算法使用规范》

您可以从[国家标准全文公开系统](https://openstd.samr.gov.cn/)在线阅读这些标准。

## SM9 current performance (for reference only):

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

