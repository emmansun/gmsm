// Copyright 2025 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build go1.24

package slhdsa

import (
	"bytes"
	"encoding/hex"
	"testing"
)

var keyCases = []struct {
	params *params
	skSeed string
	skPRF  string
	pkSeed string
	pkRoot string
}{
	{
		params: &SLHDSA128SmallSHA2,
		skSeed: "AC379F047FAAB2004F3AE32350AC9A3D",
		skPRF:  "829FFF0AA59E956A87F3971C4D58E710",
		pkSeed: "0566D240CC519834322EAFBCC73C79F5",
		pkRoot: "A4B84F02E8BF0CBD54017B2D3C494B57",
	},
	{
		params: &SLHDSA128SmallSM3,
		skSeed: "AC379F047FAAB2004F3AE32350AC9A3D",
		skPRF:  "829FFF0AA59E956A87F3971C4D58E710",
		pkSeed: "0566D240CC519834322EAFBCC73C79F5",
		pkRoot: "5EECDA31C1C8406AA02F846831D0B7FD",
	},
	{
		params: &SLHDSA128SmallSHAKE,
		skSeed: "2A2CCF3CD8F9F86E131BE654CFF6C0B4",
		skPRF:  "FDFCEB1AA2F0BA2C3C1388194F6116C7",
		pkSeed: "890CC7F4A46FE6C34D3F26A62FF962E1",
		pkRoot: "E8C88D2BDCBA6F66E50403E77FA92EFE",
	},
	{
		params: &SLHDSA128FastSHA2,
		skSeed: "AED6F6F5C5408BBFFA1136BC9049A701",
		skPRF:  "4D4CE0711E176A0C8A023508A692C207",
		pkSeed: "74D98D5000AF53B98F36389A1292BED3",
		pkRoot: "F4A650C56C426FCFDB88E3355459440C",
	},
	{
		params: &SLHDSA128FastSM3,
		skSeed: "AED6F6F5C5408BBFFA1136BC9049A701",
		skPRF:  "4D4CE0711E176A0C8A023508A692C207",
		pkSeed: "74D98D5000AF53B98F36389A1292BED3",
		pkRoot: "876557FCFD59E660B26D2C607E81BDDA",
	},
	{
		params: &SLHDSA128FastSHAKE,
		skSeed: "CD4A308C03D970508572C0815D7488B7",
		skPRF:  "F3FD6D2DCC7E5120FA544846AEDDED81",
		pkSeed: "BC435C3E66E4C2E4FBC09779DA5F74D4",
		pkRoot: "4EA0E0DF05C2457BCC81F59928433390",
	},
	{
		params: &SLHDSA192SmallSHA2,
		skSeed: "3BFAED208B7DC795BF3647F86E4B48BF9ADB8D6784C50155",
		skPRF:  "A20311739497C3FCB860EE47E09EDE036F7AE8A939155BC0",
		pkSeed: "A67856A81A6ADBCED7F1A2780CC48A06681BA5E8C7938506",
		pkRoot: "BD031BC8124F95F0BAE2BECB2A3FBBAEC453C04A6E918FFB",
	},
	{
		params: &SLHDSA192SmallSHAKE,
		skSeed: "915173EE0D17F30877E1D463E3DEC914E71F436867AD7615",
		skPRF:  "ED782E7033C4963A7FF0B67181DE0F0EA7EFABB326D40A86",
		pkSeed: "520660F654D537DA6934F96E5EE01B24A2F36102F68DCD10",
		pkRoot: "AA206FC79803E63850DA5E86969569FC8FB021B6C40616E2",
	},
	{
		params: &SLHDSA192FastSHA2,
		skSeed: "45D7131C727DF1CC51DB85B44E37868215DF8AEC5D1B552F",
		skPRF:  "92BC5FC8A2969FE0A522492082E994DE1DDC90FA984F847B",
		pkSeed: "8330589C20701AA9F11B473B67E1D67E1C6A2EB6C86265ED",
		pkRoot: "13A3EA895C4EEEADDE8A796BBA5233F0D86EE5CBF2A6F99C",
	},
	{
		params: &SLHDSA192FastSHAKE,
		skSeed: "855000FDFFFBA76962809C69432452F3DC79428F662C59B1",
		skPRF:  "43B1FC381C300B5ECEC7571B5DE2FCA16737E4C14911F683",
		pkSeed: "124623BA6CA1BC1B0E1A303099E2A608B0AC41715BC788A1",
		pkRoot: "9873C783378F935794ABC0313243EFC3F4A10A619CB1B1FE",
	},
	{
		params: &SLHDSA256SmallSHA2,
		skSeed: "2FBEAB9A6A80FD817E7EFCDF834EFBD4F0A36195D7598408A6A151E93DE6A557",
		skPRF:  "5D0B37D1ECBC68265B0AFEECBBA783DD27EAFDBDF3143E4AF3E5057FD5C2DADA",
		pkSeed: "1322F94917AE67D0DB420203178D591283C08BE8A1385A16CE70CD9FBAFD2AC6",
		pkRoot: "40041EAB68A4A653F89CAB7585F6B410603326DBBAAF733E7E72CB6097A4A452",
	},
	{
		params: &SLHDSA256SmallSHAKE,
		skSeed: "7D88445A7B0022F12E9E2D74755431505FF6DB1C38A8CE44864D34CFF1A12CE0",
		skPRF:  "FF2CD133AD00728EB29DD0CE881C41C640F2E28861555B59D4E0BAA0447BB542",
		pkSeed: "87A133B92EB6C81771AE002819B4C0300FA63CD7181C805096BFB16067F52A45",
		pkRoot: "CC785237C24D9235B6BC3194B79E5A9F953388EA745D7CFB87826A94E5B271D5",
	},
	{
		params: &SLHDSA256FastSHA2,
		skSeed: "B8ABC485122BE003CF36D677BEE7F47EA1017C39D96D0C56A87A7ADAD24F731A",
		skPRF:  "9222684FFACF803D44CB98222C44B3C519698B798D8F7A759FE2FA6EF173CF64",
		pkSeed: "0D50E82BEDB42E03CC967E7FD24C12777855A946FD49471184330F096A75B561",
		pkRoot: "7FB65FBD08D05F24F20CB3875E28FAC4A52A2513C7EF447B8E9328632A684CF7",
	},
	{
		params: &SLHDSA256FastSHAKE,
		skSeed: "3DE4B54A5F5FB98D6638FB3D8899355CC3582E8A397D0990CAD032D78EE9E199",
		skPRF:  "DA7F71D21D0182A99DE34E2796FE5DDE046D9C9E961DCE24C2562728BE7D9632",
		pkSeed: "B3EF3825A515E0B2E4164DB7EC805B4CF1C7A2DE6E63D7DF359B99B1F3063F25",
		pkRoot: "AEC38FF53C46AAD930166957CA0DB5C5466D0CBE9A11970987A230EBBB5450A4",
	},
}

func TestGenerateKeyInternal(t *testing.T) {
	for _, tc := range keyCases {
		skSeed, _ := hex.DecodeString(tc.skSeed)
		skPRF, _ := hex.DecodeString(tc.skPRF)
		pkSeed, _ := hex.DecodeString(tc.pkSeed)
		pkRoot, _ := hex.DecodeString(tc.pkRoot)

		privKey, err := generateKeyInernal(skSeed, skPRF, pkSeed, tc.params)
		if err != nil {
			t.Errorf("generateKeyInernal(%x,%x,%x) = %v", skSeed, skPRF, pkSeed, err)
			continue
		}

		if !bytes.Equal(privKey.PublicKey.root[:tc.params.n], pkRoot) {
			t.Errorf("generateKeyInernal(%x,%x,%x) = %x, expected=%x", skSeed, skPRF, pkSeed, privKey.PublicKey.root[:tc.params.n], pkRoot)
		}
	}
}
