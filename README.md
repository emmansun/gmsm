**SM2 encryption Benchmark**

    P-256/SM2(No tuning)
    goos: windows
    goarch: amd64
    pkg: gmsm/sm2
    BenchmarkLessThan32-6   	     210	   5665861 ns/op	   0.01 MB/s	 2601864 B/op	   27725 allocs/op
    PASS
    ok  	gmsm/sm2	5.629s
    
    P-256/SM2(with P256/SM2 curve implementation, first version)
    goos: windows
    goarch: amd64
    pkg: gmsm/sm2
    BenchmarkLessThan32_P256SM2-6   	    1027	   1169516 ns/op	    3874 B/op	      74 allocs/op
    PASS
    ok  	gmsm/sm2	1.564s

    goos: windows(with amd64 curve implementation, first version)
    goarch: amd64
    pkg: github.com/emmansun/gmsm/sm2
    BenchmarkLessThan32_P256SM2-6   	   10447	    115618 ns/op	    2357 B/op	      46 allocs/op
    PASS
    ok  	github.com/emmansun/gmsm/sm2	2.199s

    P-256
    goos: windows
    goarch: amd64
    pkg: gmsm/sm2
    BenchmarkMoreThan32-6   	   13656	     86252 ns/op	    3141 B/op	      50 allocs/op
    PASS
    ok  	gmsm/sm2	4.139s
