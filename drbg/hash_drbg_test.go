package drbg

import (
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"hash"
	"testing"

	"github.com/emmansun/gmsm/sm3"
)

var tests = []struct {
	gm                    bool
	md                    hash.Hash
	entropyInput          string
	nonce                 string
	personalizationString string
	v0                    string
	c0                    string
	entropyInputReseed    string
	additionalInputReseed string
	v1                    string
	c1                    string
	additionalInput1      string
	v2                    string
	additionalInput2      string
	returnbits1           string
	v3                    string
}{
	{
		false,
		sha1.New(),
		"1610b828ccd27de08ceea032a20e9208",
		"492cf1709242f6b5",
		"",
		"9e8301725d5f133b4ab7d329fd2f87ae5f89d96a9dd7e2b98beee1c707b8c3fe412d1125b58bae5dc08a11dac3be4a3147347160fef218",
		"e5e12450450efe5fdc777c95b8c23c938fcd592e2d788f12461936e4a16131b1f2d11ce7f0159ee1e635e62f3df8bda4fea077ad5f9d06",
		"72d28c908edaf9a4d1e526d8f2ded544",
		"",
		"745c659f2944829ca6e209c8ca2dddecf9f1861383e34e94007a3a51b8444fd5ae738e7d9c0d5e69aa97ee16c49cfd2432eb32ba5738fa",
		"a1fc40009357a024d878818cf6f979a88d4cc5d760b308ae1a5b9f067972e6f7cf92ddb129a8d3c1bb0005bcf3f8871fd65e794f1990b7",
		"",
		"1658a59fbc9c22c17f5a8b55c1275795873e4beae49657421ad5d95831b736cd7e066c738bcbb343933c411c7c17917593c03a77bed56b",
		"",
		"56f33d4fdbb9a5b64d26234497e9dcb87798c68d08f7c41199d4bddf97ebbf6cb5550e5d149ff4d5bd0f05f25a6988c17436396227184af84a564335658e2f8572bea333eee2abff22ffa6de3e22aca2",
		"b854e5a04ff3c2e657d30ce2b820d13e148b11c245495ff03531785eab2a1dc54d994a5597b15c5b10001f49606c88b4ff0d61acb61820",
	},
	{
		false,
		sha1.New(),
		"d9bab5cedca96f6178d64509a0dfdc5e",
		"dad8989414450e01",
		"",
		"5e07c6b72aaa5afcaab1cc3929239debde7f590886ba5bf558b90345f8518cb87a2bccdefa0c22283538e505efdaf2bd643059fd842106",
		"362aafd121de087197466e77b9bf6924841c01bd5fa98d6bc0a75b95d91166ec80e1516a10fff3216a7ad0b0c6e4f4d9708ccd69677134",
		"c6bad074c5906786f5e1f32099f5b491",
		"3e6bf46f4daa3825d7194e694e7752f7",
		"66165aed47c55d963e25aa856553e0a5a590ed06e3cec66254c6a3d8ac8b30da6b334145c466a025b445938d84151bbdbe1509e1cc7189",
		"bca1bfd5a1c718d53cd73eb584eedc19d5a3396bf558f659ae673106d0abe1f194e695ca67c2e8ddc8ee95ace21e6b12751faa695ac727",
		"04fa2895aa5a6f8c5743343b805e5ea4",
		"22b81ac2e98c766b7afce93aea42bcbf7b342672d927bcbc032dd4df7d3712cc0019d750e811a157c71db2340f6d022bd498dbd4dd4669",
		"df5dc459dff02aa2f052d721ec607230",
		"c48b89f9da3f748245555d5d033b693dd71a4df5690205cefcd720113cc24e098936ff5e77b541535870b339468cdd8d6faf8c56163a700a75b23e599b5aecf16f3baf6d5f2419971f24f446720feabe",
		"df59da988b538f40b7d427f06f3198d950d75fdece80b315b19505e64de2f4bd95006d7c6d774e39237115e40aca2d4a88ddec412b67ee",
	},
	{
		false,
		sha256.New(),
		"63363377e41e86468deb0ab4a8ed683f6a134e47e014c700454e81e95358a569",
		"808aa38f2a72a62359915a9f8a04ca68",
		"",
		"32ab605ddc8d5651093b8a59bd9d3adea1249e21a69e2e4a3967515fa03ad41ccf5b126eb9f3b268080c952df88241fe4cc27bbcbbbed5",
		"8ea2691d1915ebb4975593ca3fbad0ba137026d901a95950a207c41dc7773e15c1e85f4a5f91002866830bebe5c4ee1785b839323fbb44",
		"e62b8a8ee8f141b6980566e3bfe3c04903dad4ac2cdf9f2280010a6739bc83d3",
		"",
		"59177d93843f0550f33933a51eb488168699ab9c85651536a61f7ec71e8b274a151f17e56becaf531dcfc955f2f1adb6536d51b256d53c",
		"897c02699f4254e1f33c94f7bfa85da3826df6c2590ed0815cbced36d77aa3375a1582ffc1c887416afd1ba0f04b6ddff81a2b0e5b844d",
		"",
		"e2937ffd23815a32e675c89cde5ce5ba0907a25ede73e61c9ec76d67da582c94001fda32b60ec40202a164c6a4d66411cc6b99b1284617",
		"",
		"04eec63bb231df2c630a1afbe724949d005a587851e1aa795e477347c8b056621c18bddcdd8d99fc5fc2b92053d8cfacfb0bb8831205fad1ddd6c071318a6018f03b73f5ede4d4d071f9de03fd7aea105d9299b8af99aa075bdb4db9aa28c18d174b56ee2a014d098896ff2282c955a81969e069fa8ce007a180183a07dfae17",
		"6c0f8266c2c3af14d9b25d949e05435d8b7599213782b6eac6cd90a10d48e1c96088f5dba20241b68cb64bb05028c35e5558ef8a6edca6",
	},
	{
		false,
		sha256.New(),
		"9cfb7ad03be487a3b42be06e9ae44f283c2b1458cec801da2ae6532fcb56cc4c",
		"a20765538e8db31295747ec922c13a69",
		"",
		"8037eb9f243343f8af8c756475ea998f47a487c64dfad9945391004b08cf1a9102d4669492f554b543d820f18a90f453ad53acaf39f0c9",
		"ed540b209e044dc2591923883c9a3b1b7c265bc053c40aa91971b09be4d3b3034b05f197a09c6339c7c16de14a20e29ea17bf11cbdb248",
		"96bc8014f90ebdf690db0e171b59cc46c75e2e9b8e1dc699c65c03ceb2f4d7dc",
		"6fea0894052dab3c44d503950c7c72bd7b87de87cb81d3bb51c32a62f742286d",
		"cf9d4dd8a2c4fb507addbe849643acef2bcf6a4403082a026d50371bc7f2ea9d3975790238af78b750ef0334b7e42e0b1e71aeb97c6029",
		"e16ed4378e0342deff3003334eae72709c31f5b4004ab9870ee73a6ab4c7eb6f18027c717bf8c94ccc1e06ce5a3afaacb431e2f860f7ed",
		"d3467c78563b74c13db7af36c2a964820f2a9b1b167474906508fdac9b2049a6",
		"b10c221030c83e2f7a0dc1b7e4f21f5fc8015ff80352e416298fcc88847c8d0ca970964fbaa83f411e07fb6d6ac42b95a2c1abce0fc285",
		"5840a11cc9ebf77b963854726a826370ffdb2fc2b3d8479e1df5dcfa3dddd10b",
		"71c1154a2a7a3552413970bf698aa02f14f8ea95e861f801f463be27868b1b14b1b4babd9eba5915a6414ab1104c8979b1918f3094925aeab0d07d2037e613b63cbd4f79d9f95c84b47ed9b77230a57515c211f48f4af6f5edb2c308b33905db308cf88f552c8912c49b34e66c026e67b302ca65b187928a1aba9a49edbfe190",
		"927af647becb810e793dc4eb33a091d0643355ac039d9e1e4d60a2ac023dca791d46f5e560b237047371aa1d629988772af7b96c0d0a07",
	},
	{
		false,
		sha512.New(),
		"3144e17a10c856129764f58fd8e4231020546996c0bf6cff8e91c24ee09be333",
		"b16fcb1cf0c010f31feab733588b8e04",
		"",
		"3a85ca10eac683d6a9270594d17f33a21dad7b9b259c2a174462a5e0c909a133db84b4ee2bdb0f72cdcef7d62854e535468452285dbe8e46bed3965dc9c66952defa48879493edc01bc07ed4973c115cfdd9947a708465351b78b804652ec7cbe7f6e2a09193fa352ff991d38c94ac",
		"74ea437c49126ff361feab5639a8ad318d455c94b3f999ff1606f592c27f8bf0be562c7bffa297de8512ef44b0dfc8db5cb17c9692ac0d80f066961e6426084108089eee4a759d5309ec861668ddeb1c31ceef26edad678b6f36c3ebcb9c936cafcee3d9a96ae6554e22d42888ab07",
		"a0b3584c2c8412f618406834404d1eb0ce999ba28966054d7e497e0db608b967",
		"",
		"b37f9aa39c5a80df56c040402407960ef6f8892d1a688ffc93bad6ebe6af44d55ccd66c1f44eb531e9dac1c9447681d7b27b2b703b490032696b32330b5edd123e5ece7c40efe70a29822ea8e4e454bb72085c6b037a8652ec227f899dd01455db8ee7b6b2e92114f6f9fb678e6332",
		"908ad858db2c5d21fa1cd860217bd75ad0ba1df2fd24e303964c01113a0b024a1e53640d5ae339040b4357c1f3c0be2f14607b1385e968183c53ecd9a33ddb04b3ac36dfc1353d8571159a0b31b81b5d3de24b8ae6530c838fa8712ea5d4d58763f2be0ab1989987c56bfd315df521",
		"",
		"440a72fc7786de0150dd18a045836d69c7b2a720178d73002a06d7fd20ba471f7b20cacf4f31ee35f51e198b383740fb34724a0747e261c800fa0f744bdc842d37199f6acf5f4af041a6600878cf72a7ceaa750fa1c23546f962afe97c055683eaf5131d9f9c882edb93c50adba963",
		"",
		"efa35dd0362adb7626456b36fac74d3c28d01d926420275a28bea9c9dd7547c15e7931852ac1277076567535239c1f429c7f75cf74c2267deb6a3e596cf326156c796941283b8d583f171c2f6e3323f7555e1b181ffda30507210cb1f589b23cd71880fd44370cacf43375b0db7e336f12b309bfd4f610bb8f20e1a15e253a4fe511a027968df0b105a1d73aff7c7a826d39f640dfb8f522259ed402282e2c2e9d3a498f51725fe4141b06da5598a42ac1e0494e997d566a1a39b676b96a6003a4c5db84f246584ee65af70ff2160278166da16d91c9b8f2deb02751a1088ad6be4e80ef966eb73e66bc87cad87c77c0b34a21ba1da0ba6d16ca5046dc4abda0",
		"d4954b5552b33b234af9f10066ff44c4986cc51314b25603c052d90e5ac5496999742edcaa15273a0061714d2bf7ffb32b7000bfdeb10605f36174eb33a48a4cc007c23bb03597b4d8a6373ca7037e8a8ff08f63779da9e61878b1886cb084ba68ceef8ad4e5ba7720acbd3b262822",
	},
	{
		false,
		sha512.New(),
		"c73a7820f0f53e8bbfc3b7b71d994143cf6e98642e9ea6d8df5dccbc43db8720",
		"20cc9834b588adcb1bbde64f0d2a34cb",
		"",
		"852d1b4fdd41cd7e0f597c45c8e4b401a5fecf9229b6072451ca65b5289882c686e7919922ce82de2faac83cd4c4eddfa2cdcf6244a4d2acdd34c0232136409bb50ea24d0c33fcfd1aaf1cc110b5353d32e4e6df59ae25ec124000de62fcfa8bb4cb3f3b72e2da2066ef00cd66d9e9",
		"f7b0c9cf2ccf58fd8c8b69daa4cf24a874c95b57a9f5be16aaa71ec30070ac8f222fe21788fec14b8a9ad7ad20912c05a6f94548646779a16c787b135ce8d08c49f7e234cbd2c7733571f5ad6479b5fc50403496581b4861ef8ec848affbd2077ab164fc6bb2dd7b008a650504bfd8",
		"12dd2aca8879046d23165c60f8aedc20415783e156d42a94346826aaeb02eacf",
		"9b59ff78a34eabe0060c2792ca9b49e9781e6b802badf7dbde27caaed3343706",
		"181a302352d9ebf0b669730b2441a9f4c16a4b9d25ebc84ed01c460d293cd3e8b7bff1aca32b0ea8d281df0ef8d1ae09d4cf97690c944f4713adb9ede90763f3ed77081c37c0fc60f8b60b5108cf6276c80db14a82aaef1bf8da03781445cfcc7cdc02b1c7a2740874dd948118f7ef",
		"28b638d631f054eba562320e9d151f905863dd6c04d8ba41167bcf3b0236d4e5dde1dc7bf690e61b4a65997bd9c67ff908fe7e2443d01c8eac15b2ea5c80ba89f09aa9b8a81d56124bb71586812827f463de90318727102dbd5e59ca5f1af78ab73844695eee0977b754854e525097",
		"dc74a9e480a6ff6f6bce53ab9c7bdde4b13d70fb5196cdd5e3a0555ccf06fe91",
		"40d068f984ca40dc5bcba519c156c98519ce29092ac4828fe69815482b73a8ce95a1ce2899bbf4c41ce7788ad2982e3cea3266f4cadc50ae528dc61aa7c521489869e3efc6c82ccefbbab45673e0f59d5654cf910fa146d984a42c5f17fb60340c86d0d07c7e2f2e6df3cffd722a0e",
		"8f3f229011209b2f399096afb054bccca6bc46aaee98845838fb1fb78b66f3bd",
		"e6c96442582811ec90e587525f36c555e2fd6361a0c5b0284917a4fa6f6e8ace83f11a1fb26cea6692b225ae7c5be286dd27471f323d7a2e4431722bb337b1ba0e648ea2e9f0918b50e9111f2377636ba69b0e1cb5295078d76c549c8656940eb15ca5aded7adc46e6fa4b86948f212fea3f3befdeece8b20e420ca84c760196ddf0b074df0a9f097a5db8f6125800f5fe746a62df1208042f1255b524465a17efcf6a537612968430e2adcff30f7407a51ed7305334384e512e003642cca175636819f021c76a2f44e89e6fe39cf164477910379cd314f735c357f9379de22495276b401c98ffb09a6dc03e484b355a9464511401eeaa05b4556e73b55227f8",
		"6986a1cfb6ba95c8012dd7285e6be915723206752f9d3cd0fd13e4832daa7db47383aaa4904cdadf674d1206ac5eafa99de1304fc0b6a1b5e32e34a7f4141e89353878c0d3f6a0ba5b9ed452d61260de9e5acbf8134485b3b9e990f59f34d4d43307e40ad0d0a505efdb24b72f807b",
	},
	{
		true,
		sm3.New(),
		"63363377e41e86468deb0ab4a8ed683f6a134e47e014c700454e81e95358a569",
		"808aa38f2a72a62359915a9f8a04ca68",
		"",
		"7a070cb0c9806fe6a74c0396825642690fc458e76397b75b5977e8a5e693687a703b08c8fbb9e9a600d181c530e889336390818ca2c271",
		"218bcd7e3a836cc2e275e660a29fab9c1b3e5596275d8f3141f8c7fb3b285b9edda112e7e85e8492c9b4ed9c1ea466b00cce3be9c10a03",
		"e62b8a8ee8f141b6980566e3bfe3c04903dad4ac2cdf9f2280010a6739bc83d3",
		"",
		"99ec25b65124082695c773d8ef03cc2b31a916956bb582752399c3951c9956d21a73a08091f47401e7133844ea6544361961c7cc4d7e6e",
		"c7d8714c59bce8c8b033b99ce3577acd68a3b10151cc0a60c4b2790e56ce47592574d6909fab7fc551d33402f364aaa4d6fcc83989b9c7",
		"",
		"61c49702aae0f0ef45fb2d75d25b46f89a4cc796bd818d0c7bd0a23a3938e9c81783160d900852f33241399b1a69f7c80bc9865e182676",
		"",
		"00d98d35a2fab8df23e9e1fb9aad143d62c0759eb79e15c37e8f2bc5064e68da",
		"299d084f049dd9b7f62ee712b5b2c1c602f078980f4d9816d8f2baf38765be984b6c493497af30f68a56072404f27e45af419d04eb9e35",
	},
	{
		true,
		sm3.New(),
		"9cfb7ad03be487a3b42be06e9ae44f283c2b1458cec801da2ae6532fcb56cc4c",
		"a20765538e8db31295747ec922c13a69",
		"",
		"997cd31a7032c8643ca56de1d34ff4f930b13192e17c8947bcaf9b9d010cf79805511255c7ea18b41cde77e491ca943861ec29780f3f36", // v0
		"4c5b167d27fa9d40cbc45d0d9f3c52504a1cb5aa2f37a3fa812037bd1e458412ecff0641dd5cb2785d0f8044151b42842777211547b457", // c0
		"96bc8014f90ebdf690db0e171b59cc46c75e2e9b8e1dc699c65c03ceb2f4d7dc",
		"6fea0894052dab3c44d503950c7c72bd7b87de87cb81d3bb51c32a62f742286d",
		"e3d804eda66df62f425c41047c5812fca471c8236395c92d4bd834c2e52d606be6ad3da8973df16e8567bcb16e45f2842ace91bf6dfeb3", // v1
		"1a1b2fffca26953626e0fa3afd377e14e63c5e81275b39f1436b707efb2c3059e6ced8fdb238a45bf05aae9f2417dbf5c4f89d3772f324", // c1
		"d3467c78563b74c13db7af36c2a964820f2a9b1b167474906508fdac9b2049a6",
		"fdf334ed70948b65693d3b3f798f91118aae26a48af1045be386984b75695902870479c3c53593d332d195ee7f1bed45fc5069cc4f9948", // v2
		"5840a11cc9ebf77b963854726a826370ffdb2fc2b3d8479e1df5dcfa3dddd10b",
		"48709db5509a03d6131775fbbfe74fe52611e760d22fde61e274a295f4354d67",
		"180e64ed3abb209b901e357a76c70f2670ea8525b24c401d146b70b178e33d8fd10f7680c50bbe1f9773ba664dd14cd25d329c380bf399", // v3
	},
}

func TestHashDRBG(t *testing.T) {
	for _, test := range tests {
		entropyInput, _ := hex.DecodeString(test.entropyInput)
		nonce, _ := hex.DecodeString(test.nonce)
		personalizationString, _ := hex.DecodeString(test.personalizationString)
		v0, _ := hex.DecodeString(test.v0)
		c0, _ := hex.DecodeString(test.c0)
		hd, err := NewHashDrbg(test.md, SECURITY_LEVEL_ONE, test.gm, entropyInput, nonce, personalizationString)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(hd.v[:len(v0)], v0) {
			t.Errorf("not same v0 %s", hex.EncodeToString(hd.v[:len(v0)]))
		}
		if !bytes.Equal(hd.c[:len(c0)], c0) {
			t.Errorf("not same c0 %s", hex.EncodeToString(hd.c[:len(c0)]))
		}
		// Reseed
		entropyInputReseed, _ := hex.DecodeString(test.entropyInputReseed)
		additionalInputReseed, _ := hex.DecodeString(test.additionalInputReseed)
		v1, _ := hex.DecodeString(test.v1)
		c1, _ := hex.DecodeString(test.c1)
		err = hd.Reseed(entropyInputReseed, additionalInputReseed)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(hd.v[:len(v0)], v1) {
			t.Errorf("not same v1 %s", hex.EncodeToString(hd.v[:len(v0)]))
		}
		if !bytes.Equal(hd.c[:len(c0)], c1) {
			t.Errorf("not same c1 %s", hex.EncodeToString(hd.c[:len(c0)]))
		}
		// Generate 1
		returnbits1, _ := hex.DecodeString(test.returnbits1)
		v2, _ := hex.DecodeString(test.v2)
		output := make([]byte, len(returnbits1))
		additionalInput1, _ := hex.DecodeString(test.additionalInput1)
		hd.Generate(output, additionalInput1)
		if !bytes.Equal(hd.v[:len(v0)], v2) {
			t.Errorf("not same v2 %s", hex.EncodeToString(hd.v[:len(v0)]))
		}
		// Generate 2
		v3, _ := hex.DecodeString(test.v3)
		additionalInput2, _ := hex.DecodeString(test.additionalInput2)
		hd.Generate(output, additionalInput2)
		if !bytes.Equal(hd.v[:len(v0)], v3) {
			t.Errorf("not same v3 %s", hex.EncodeToString(hd.v[:len(v0)]))
		}
		if !bytes.Equal(returnbits1, output) {
			t.Errorf("not expected return bits %s", hex.EncodeToString(output))
		}
	}
}

func TestGmHashDRBG_Validation(t *testing.T) {
	entropyInput := make([]byte, 64)
	_, err := NewHashDrbg(sm3.New(), SECURITY_LEVEL_ONE, true, entropyInput[:16], entropyInput[16:24], nil)
	if err == nil {
		t.Fatalf("expected error here")
	}
	_, err = NewHashDrbg(sm3.New(), SECURITY_LEVEL_ONE, true, entropyInput[:32], entropyInput[32:40], nil)
	if err == nil {
		t.Fatalf("expected error here")
	}
	hd, err := NewHashDrbg(sm3.New(), SECURITY_LEVEL_ONE, true, entropyInput[:32], entropyInput[32:48], nil)
	if err != nil {
		t.Fatal(err)
	}
	err = hd.Reseed(entropyInput[:16], nil)
	if err == nil {
		t.Fatalf("expected error here")
	}
}
