package bn256

import "testing"

func BenchmarkGfP12Copy(b *testing.B) {
	x := &gfP12{
		testdataP4,
		testdataP4,
		testdataP4,
	}
	res := &gfP12{}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		gfp12Copy(res, x)
	}
}

func gfpCopyForTest(res, in *gfP) {
	res[0] = in[0]
	res[1] = in[1]
	res[2] = in[2]
	res[3] = in[3]
}

func gfp2CopyForTest(res, in *gfP2) {
	gfpCopyForTest(&res.x, &in.x)
	gfpCopyForTest(&res.y, &in.y)
}

func gfp4CopyForTest(res, in *gfP4) {
	gfp2CopyForTest(&res.x, &in.x)
	gfp2CopyForTest(&res.y, &in.y)
}

func gfp12CopyForTest(res, in *gfP12) {
	gfp4CopyForTest(&res.x, &in.x)
	gfp4CopyForTest(&res.y, &in.y)
	gfp4CopyForTest(&res.z, &in.z)
}

func BenchmarkGfP12Set(b *testing.B) {
	x := &gfP12{
		testdataP4,
		testdataP4,
		testdataP4,
	}
	res := &gfP12{}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		gfp12CopyForTest(res, x)
	}
}
