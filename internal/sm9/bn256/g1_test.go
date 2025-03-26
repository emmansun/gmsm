package bn256

import (
	"testing"
)

func TestG1AddNeg(t *testing.T) {
	g1, g2 := &G1{}, &G1{}

	g1.Neg(Gen1)
	g2.Add(g1, Gen1)
	if !g2.p.IsInfinity() {
		t.Fail()
	}
	g3 := &G1{}
	g3.Set(Gen1)
	if !g3.Equal(Gen1) {
		t.Fail()
	}
}

func TestG1AddSame(t *testing.T) {
	g1, g2 := &G1{}, &G1{}
	g1.Add(Gen1, Gen1)
	g2.Double(Gen1)

	if !g1.Equal(g2) {
		t.Fail()
	}
}

func TestCurvePointDouble(t *testing.T) {
	p := &curvePoint{}
	p.Double(p)
	if !p.IsInfinity() {
		t.Fail()
	}
}

func TestCurvePointDobuleComplete(t *testing.T) {
	t.Parallel()
	t.Run("normal case", func(t *testing.T) {
		p2 := &curvePoint{}
		p2.DoubleComplete(curveGen)
		p2.AffineFromProjective()

		p3 := &curvePoint{}
		curvePointDouble(p3, curveGen)
		p3.AffineFromJacobian()

		if !p2.Equal(p3) {
			t.Errorf("Got %v, expected %v", p2, p3)
		}
	})

	t.Run("exception case: IsInfinity", func(t *testing.T) {
		p1 := &curvePoint{}
		p1.SetInfinity()
		p2 := &curvePoint{}
		p2.DoubleComplete(p1)
		p2.AffineFromProjective()
		if !p2.IsInfinity() {
			t.Fatal("should be infinity")
		}
	})
}

func TestCurvePointAddComplete(t *testing.T) {
	t.Parallel()
	t.Run("normal case", func(t *testing.T) {
		p1 := &curvePoint{}
		curvePointDouble(p1, curveGen)
		p1.AffineFromJacobian()

		p2 := &curvePoint{}
		p2.AddComplete(p1, curveGen)
		p2.AffineFromProjective()

		p3 := &curvePoint{}
		curvePointAdd(p3, curveGen, p1)
		p3.AffineFromJacobian()

		if !p2.Equal(p3) {
			t.Errorf("Got %v, expected %v", p2, p3)
		}
	})
	t.Run("exception case: double", func(t *testing.T) {
		p2 := &curvePoint{}
		p2.AddComplete(curveGen, curveGen)
		p2.AffineFromProjective()

		p3 := &curvePoint{}
		curvePointDouble(p3, curveGen)
		p3.AffineFromJacobian()
		if !p2.Equal(p3) {
			t.Errorf("Got %v, expected %v", p2, p3)
		}
	})
	t.Run("exception case: neg", func(t *testing.T) {
		p1 := &curvePoint{}
		p1.Neg(curveGen)
		p2 := &curvePoint{}
		p2.AddComplete(curveGen, p1)
		p2.AffineFromProjective()
		if !p2.IsInfinity() {
			t.Fatal("should be infinity")
		}
	})
	t.Run("exception case: IsInfinity", func(t *testing.T) {
		p1 := &curvePoint{}
		p1.SetInfinity()
		p2 := &curvePoint{}
		p2.AddComplete(curveGen, p1)
		p2.AffineFromProjective()
		if !p2.Equal(curveGen) {
			t.Fatal("should be curveGen")
		}
		p2.AddComplete(p1, curveGen)
		p2.AffineFromProjective()
		if !p2.Equal(curveGen) {
			t.Fatal("should be curveGen")
		}
		p2.AddComplete(p1, p1)
		p2.AffineFromProjective()
		if !p2.IsInfinity() {
			t.Fatal("should be infinity")
		}
	})
}

type g1BaseMultTest struct {
	k string
}

var baseMultTests = []g1BaseMultTest{
	{
		"112233445566778899",
	},
	{
		"112233445566778899112233445566778899",
	},
	{
		"6950511619965839450988900688150712778015737983940691968051900319680",
	},
	{
		"13479972933410060327035789020509431695094902435494295338570602119423",
	},
	{
		"13479971751745682581351455311314208093898607229429740618390390702079",
	},
	{
		"13479972931865328106486971546324465392952975980343228160962702868479",
	},
	{
		"11795773708834916026404142434151065506931607341523388140225443265536",
	},
	{
		"784254593043826236572847595991346435467177662189391577090",
	},
	{
		"13479767645505654746623887797783387853576174193480695826442858012671",
	},
	{
		"205688069665150753842126177372015544874550518966168735589597183",
	},
	{
		"13479966930919337728895168462090683249159702977113823384618282123295",
	},
	{
		"50210731791415612487756441341851895584393717453129007497216",
	},
	{
		"26959946667150639794667015087019625940457807714424391721682722368041",
	},
	{
		"26959946667150639794667015087019625940457807714424391721682722368042",
	},
	{
		"26959946667150639794667015087019625940457807714424391721682722368043",
	},
	{
		"26959946667150639794667015087019625940457807714424391721682722368044",
	},
	{
		"26959946667150639794667015087019625940457807714424391721682722368045",
	},
	{
		"26959946667150639794667015087019625940457807714424391721682722368046",
	},
	{
		"26959946667150639794667015087019625940457807714424391721682722368047",
	},
	{
		"26959946667150639794667015087019625940457807714424391721682722368048",
	},
	{
		"26959946667150639794667015087019625940457807714424391721682722368049",
	},
	{
		"26959946667150639794667015087019625940457807714424391721682722368050",
	},
	{
		"26959946667150639794667015087019625940457807714424391721682722368051",
	},
	{
		"26959946667150639794667015087019625940457807714424391721682722368052",
	},
	{
		"26959946667150639794667015087019625940457807714424391721682722368053",
	},
	{
		"26959946667150639794667015087019625940457807714424391721682722368054",
	},
	{
		"26959946667150639794667015087019625940457807714424391721682722368055",
	},
	{
		"26959946667150639794667015087019625940457807714424391721682722368056",
	},
	{
		"26959946667150639794667015087019625940457807714424391721682722368057",
	},
	{
		"26959946667150639794667015087019625940457807714424391721682722368058",
	},
	{
		"26959946667150639794667015087019625940457807714424391721682722368059",
	},
	{
		"26959946667150639794667015087019625940457807714424391721682722368060",
	},
}

func BenchmarkAddPoint(b *testing.B) {
	p1 := &curvePoint{}
	curvePointDouble(p1, curveGen)
	p1.AffineFromJacobian()
	p2 := &curvePoint{}

	b.Run("Add complete", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			p2.AddComplete(curveGen, p1)
		}
	})

	b.Run("Add traditional", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			curvePointAdd(p2, curveGen, p1)
		}
	})
}

func BenchmarkDoublePoint(b *testing.B) {
	p2 := &curvePoint{}

	b.Run("Double complete", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			p2.DoubleComplete(curveGen)
		}
	})

	b.Run("Double traditional", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			curvePointDouble(p2, curveGen)
		}
	})

}
