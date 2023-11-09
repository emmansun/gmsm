//go:build (!amd64 && !arm64) || purego

package bn256

func gfP12MovCond(res, a, b *gfP12, cond int) {
	res.Select(a, b, cond)
}

func curvePointMovCond(res, a, b *curvePoint, cond int) {
	res.x.Select(&a.x, &b.x, cond)
	res.y.Select(&a.y, &b.y, cond)
	res.z.Select(&a.z, &b.z, cond)
	res.t.Select(&a.t, &b.t, cond)
}

func twistPointMovCond(res, a, b *twistPoint, cond int) {
	// Select sets q to p1 if cond == 1, and to p2 if cond == 0.
	res.x.Select(&a.x, &b.x, cond)
	res.y.Select(&a.y, &b.y, cond)
	res.z.Select(&a.z, &b.z, cond)
	res.t.Select(&a.t, &b.t, cond)
}

func gfpCopy(res, in *gfP) {
	res[0] = in[0]
	res[1] = in[1]
	res[2] = in[2]
	res[3] = in[3]
}

func gfp2Copy(res, in *gfP2) {
	gfpCopy(&res.x, &in.x)
	gfpCopy(&res.y, &in.y)
}

func gfp4Copy(res, in *gfP4) {
	gfpCopy(&res.x.x, &in.x.x)
	gfpCopy(&res.x.y, &in.x.y)
	gfpCopy(&res.y.x, &in.y.x)
	gfpCopy(&res.y.y, &in.y.y)
}

func gfp6Copy(res, in *gfP6) {
	gfpCopy(&res.x.x, &in.x.x)
	gfpCopy(&res.x.y, &in.x.y)
	gfpCopy(&res.y.x, &in.y.x)
	gfpCopy(&res.y.y, &in.y.y)
	gfpCopy(&res.z.x, &in.z.x)
	gfpCopy(&res.z.y, &in.z.y)
}

func gfp12Copy(res, in *gfP12) {
	gfpCopy(&res.x.x.x, &in.x.x.x)
	gfpCopy(&res.x.x.y, &in.x.x.y)
	gfpCopy(&res.x.y.x, &in.x.y.x)
	gfpCopy(&res.x.y.y, &in.x.y.y)

	gfpCopy(&res.y.x.x, &in.y.x.x)
	gfpCopy(&res.y.x.y, &in.y.x.y)
	gfpCopy(&res.y.y.x, &in.y.y.x)
	gfpCopy(&res.y.y.y, &in.y.y.y)

	gfpCopy(&res.z.x.x, &in.z.x.x)
	gfpCopy(&res.z.x.y, &in.z.x.y)
	gfpCopy(&res.z.y.x, &in.z.y.x)
	gfpCopy(&res.z.y.y, &in.z.y.y)
}
