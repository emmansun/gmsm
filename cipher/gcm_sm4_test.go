package cipher_test

import (
	"bytes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"io"
	"testing"

	"github.com/emmansun/gmsm/sm4"
)

var sm4GCMTests = []struct {
	key, nonce, plaintext, ad, result string
}{
	{ // GB/T 36624-2018 C.5 1
		"00000000000000000000000000000000",
		"000000000000000000000000",
		"",
		"",
		"232f0cfe308b49ea6fc88229b5dc858d",
	},
	{ // GB/T 36624-2018 C.5 2
		"00000000000000000000000000000000",
		"000000000000000000000000",
		"00000000000000000000000000000000",
		"",
		"7de2aa7f1110188218063be1bfeb6d89b851b5f39493752be508f1bb4482c557",
	},
	{
		"11754cd72aec309bf52f7687212e8957",
		"3c819d9a9bed087615030b65",
		"",
		"",
		"2179109c88c0659706f7bd4aed0ea10c",
	},
	{
		"ca47248ac0b6f8372a97ac43508308ed",
		"ffd2b598feabc9019262d2be",
		"",
		"",
		"34e4a2fda29c1d4c1ec1341b4c6cc95f",
	},
	{
		"fbe3467cc254f81be8e78d765a2e6333",
		"c6697351ff4aec29cdbaabf2",
		"",
		"67",
		"8c39237d769ca5fe5edee9e193c86d7d",
	},
	{
		"8a7f9d80d08ad0bd5a20fb689c88f9fc",
		"88b7b27d800937fda4f47301",
		"",
		"50edd0503e0d7b8c91608eb5a1",
		"cf15a847573907e399b8f15b362a1572",
	},
	{
		"051758e95ed4abb2cdc69bb454110e82",
		"c99a66320db73158a35a255d",
		"",
		"67c6697351ff4aec29cdbaabf2fbe3467cc254f81be8e78d765a2e63339f",
		"df05c2ff06ae2a40745b0ef080d433b3",
	},
	{
		"77be63708971c4e240d1cb79e8d77feb",
		"e0e00f19fed7ba0136a797f3",
		"",
		"7a43ec1d9c0a5a78a0b16533a6213cab",
		"d1cae93ced2525052c4a6d53a2850fa1",
	},
	{
		"7680c5d3ca6154758e510f4d25b98820",
		"f8f105f9c3df4965780321f8",
		"",
		"c94c410194c765e3dcc7964379758ed3",
		"419289e9e805656dcd110df1875a83e4",
	},
	{
		"7fddb57453c241d03efbed3ac44e371c",
		"ee283a3fc75575e33efd4887",
		"d5de42b461646c255c87bd2962d3b9a2",
		"",
		"15e29a2a64bfc2974286e0cb84cfc7fa6c5ed60f77e0832fbbd81f07958f3934",
	},
	{
		"ab72c77b97cb5fe9a382d9fe81ffdbed",
		"54cc7dc2c37ec006bcc6d1da",
		"007c5e5b3e59df24a7c355584fc1518d",
		"",
		"97ce841f7d174d76969fb46b19e742cf28983f4439909cbb6c27662dd4fbbc73",
	},
	{ //#9
		"fe47fcce5fc32665d2ae399e4eec72ba",
		"5adb9609dbaeb58cbd6e7275",
		"7c0e88c88899a779228465074797cd4c2e1498d259b54390b85e3eef1c02df60e743f1b840382c4bccaf3bafb4ca8429bea063",
		"88319d6e1d3ffa5f987199166c8a9b56c2aeba5a",
		"2276da0e9a4ccaa2a5934c96ba1dc6b0a52b3430ca011b4db4bf6e298b3a58425402952806350fdda7ac20bc38838d7124ee7c333e395b9a94c508b6bf0ce6b2d10d61",
	},
	{ //#10
		"ec0c2ba17aa95cd6afffe949da9cc3a8",
		"296bce5b50b7d66096d627ef",
		"b85b3753535b825cbe5f632c0b843c741351f18aa484281aebec2f45bb9eea2d79d987b764b9611f6c0f8641843d5d58f3a242",
		"f8d00f05d22bf68599bcdeb131292ad6e2df5d14",
		"3175cd3cb772af34490e4f5203b6a5743cd9b3798c387b7bda2708ff82d520c35d3022767b2d0fe4addff59fb25ead69ca3dd4d73ce1b4cb53a7c4cdc6a4c1fb06c316",
	},
	{ //#11
		"2c1f21cf0f6fb3661943155c3e3d8492",
		"23cb5ff362e22426984d1907",
		"42f758836986954db44bf37c6ef5e4ac0adaf38f27252a1b82d02ea949c8a1a2dbc0d68b5615ba7c1220ff6510e259f06655d8",
		"5d3624879d35e46849953e45a32a624d6a6c536ed9857c613b572b0333e701557a713e3f010ecdf9a6bd6c9e3e44b065208645aff4aabee611b391528514170084ccf587177f4488f33cfb5e979e42b6e1cfc0a60238982a7aec",
		"9db299bb7f9d6914c4a13589cf41ab014445e4914c1571745d50508bf0f6adeaa41aa4b081a444ee82fed6769da92f5e727d004b21791f961e212a69bfe80af14e7adf",
	},
	{ //#12
		"d9f7d2411091f947b4d6f1e2d1f0fb2e",
		"e1934f5db57cc983e6b180e7",
		"73ed042327f70fe9c572a61545eda8b2a0c6e1d6c291ef19248e973aee6c312012f490c2c6f6166f4a59431e182663fcaea05a",
		"0a8a18a7150e940c3d87b38e73baee9a5c049ee21795663e264b694a949822b639092d0e67015e86363583fcf0ca645af9f43375f05fdb4ce84f411dcbca73c2220dea03a20115d2e51398344b16bee1ed7c499b353d6c597af8",
		"65c81d83857626a3ec94c913a9f44fa065b6cd61ca5dd6e15e15bb7f16e757202ef966ab1f1e8e6dcbc82f002d29ba6070f53cd79767b1cbcb8cdb656a6a4369f297fc",
	},
	{ //#13
		"fe9bb47deb3a61e423c2231841cfd1fb",
		"4d328eb776f500a2f7fb47aa",
		"f1cc3818e421876bb6b8bbd6c9",
		"",
		"d8ce306b812aa1b09299ceef804e76b1cb3f736791a5b0d93774d40c2a",
	},
	{ //#14
		"6703df3701a7f54911ca72e24dca046a",
		"12823ab601c350ea4bc2488c",
		"793cd125b0b84a043e3ac67717",
		"",
		"f42f741a51c02f71a99519f60a55c8dbdcc9a15549158cc1acd6754847",
	},
	// These cases test non-standard nonce sizes.
	{ //#15
		"1672c3537afa82004c6b8a46f6f0d026",
		"05",
		"",
		"",
		"65bde02c20351976153d5d2b49790e30",
	},
	{ //#16
		"9a4fea86a621a91ab371e492457796c0",
		"75",
		"ca6131faf0ff210e4e693d6c31c109fc5b6f54224eb120f37de31dc59ec669b6",
		"4f6e2585c161f05a9ae1f2f894e9f0ab52b45d0f",
		"b86d6055e7e07a664801ccce38172bf7d91dc20babf2c0662d635cc9111ffefb308ee64ce01afe544b6ee1a65b803cb9",
	},
	{ //#17
		"d0f1f4defa1e8c08b4b26d576392027c",
		"42b4f01eb9f5a1ea5b1eb73b0fb0baed54f387ecaa0393c7d7dffc6af50146ecc021abf7eb9038d4303d91f8d741a11743166c0860208bcc02c6258fd9511a2fa626f96d60b72fcff773af4e88e7a923506e4916ecbd814651e9f445adef4ad6a6b6c7290cc13b956130eef5b837c939fcac0cbbcc9656cd75b13823ee5acdac",
		"",
		"",
		"1edcf8ea546af4879379e7653c53dddc",
	},
	{ //#18
		"4a0c00a3d284dea9d4bf8b8dde86685e",
		"f8cbe82588e784bcacbe092cd9089b51e01527297f635bf294b3aa787d91057ef23869789698ac960707857f163ecb242135a228ad93964f5dc4a4d7f88fd7b3b07dd0a5b37f9768fb05a523639f108c34c661498a56879e501a2321c8a4a94d7e1b89db255ac1f685e185263368e99735ebe62a7f2931b47282be8eb165e4d7",
		"6d4bf87640a6a48a50d28797b7",
		"8d8c7ffc55086d539b5a8f0d1232654c",
		"193952a26ab455b3c16db216bb2597cba90a9946dec5b7d085ceb7408e",
	},
	{ //#19
		"0e18a844ac5bf38e4cd72d9b0942e506",
		"0870d4b28a2954489a0abcd5",
		"67c6697351ff4aec29cdbaabf2fbe3467cc254f81be8e78d765a2e63339fc99a66320db73158a35a255d051758e95ed4abb2cdc69bb454110e827441213ddc8770e93ea141e1fc673e017e97eadc6b968f385c2aecb03bfb32af3c54ec18db5c021afe43fbfaaa3afb29d1e6053c7c9475d8be6189f95cbba8990f95b1ebf1b3",
		"05eff700e9a13ae5ca0bcbd0484764bd1f231ea81c7b64c514735ac55e4b79633b706424119e09dcaad4acf21b10af3b33cde3504847155cbb6f2219ba9b7df50be11a1c7f23f829f8a41b13b5ca4ee8983238e0794d3d34bc5f4e77facb6c05ac86212baa1a55a2be70b5733b045cd33694b3afe2f0e49e4f321549fd824ea9",
		"f492d37084697e941acd69c3d8b53d91760f4bced0fdff529327fb03000b865fbf87133c5816bdafdd23013f1440a30835b7e4d57bb6660e14b438b19b5b07a03f74369f2a11a163e5fcc4fd7ea139982ccf589533011d8efab4a44f6154043099b39f19754a4f434290299c2faa838b92453a1b989f354e7b50ea558daf1f6a88ea50b481a4ffcdd634f324f27cb3f6",
	},
	{ //#20
		"1f6c3a3bc0542aabba4ef8f6c7169e73",
		"f3584606472b260e0dd2ebb2",
		"67c6697351ff4aec29cdbaabf2fbe3467cc254f81be8e78d765a2e63339fc99a66320db73158a35a255d051758e95ed4abb2cdc69bb454110e827441213ddc8770e93ea141e1fc673e017e97eadc6b968f385c2aecb03bfb32af3c54ec18db5c021afe43fbfaaa3afb29d1e6053c7c9475d8be6189f95cbba8990f95b1ebf1b305eff700e9a13ae5ca0bcbd0484764bd1f231ea81c7b64c514735ac55e4b79633b706424119e09dcaad4acf21b10af3b33cde3504847155cbb6f2219ba9b7df50be11a1c7f23f829f8a41b13b5ca4ee8983238e0794d3d34bc5f4e77facb6c05ac86212baa1a55a2be70b5733b045cd33694b3afe2f0e49e4f321549fd824ea90870d4b28a2954489a0abcd50e18a844ac5bf38e4cd72d9b0942e506c433afcda3847f2dadd47647de321cec4ac430f62023856cfbb20704f4ec0bb920ba86c33e05f1ecd96733b79950a3e314d3d934f75ea0f210a8f6059401beb4bc4478fa4969e623d01ada696a7e4c7e5125b34884533a94fb319990325744ee9bbce9e525cf08f5e9e25e5360aad2b2d085fa54d835e8d466826498d9a8877565705a8a3f62802944de7ca5894e5759d351adac869580ec17e485f18c0c66f17cc07cbb22fce466da610b63af62bc83b4692f3affaf271693ac071fb86d11342d8def4f89d4b66335c1c7e4248367d8ed9612ec453902d8e50af89d7709d1a596c1f41f",
		"95aa82ca6c49ae90cd1668baac7aa6f2b4a8ca99b2c2372acb08cf61c9c3805e6e0328da4cd76a19edd2d3994c798b0022569ad418d1fee4d9cd45a391c601ffc92ad91501432fee150287617c13629e69fc7281cd7165a63eab49cf714bce3a75a74f76ea7e64ff81eb61fdfec39b67bf0de98c7e4e32bdf97c8c6ac75ba43c02f4b2ed7216ecf3014df000108b67cf99505b179f8ed4980a6103d1bca70dbe9bbfab0ed59801d6e5f2d6f67d3ec5168e212e2daf02c6b963c98a1f7097de0c56891a2b211b01070dd8fd8b16c2a1a4e3cfd292d2984b3561d555d16c33ddc2bcf7edde13efe520c7e2abdda44d81881c531aeeeb66244c3b791ea8acfb6a68",
		"c40924873aa2ef1b1b7bf4e16576446b4d24ab529c3f526cdbf7ea1cf64a73f26e4077d1464d1af165b26138ae65281dc3ca0d0998cce7b3c4fe2de5007c5c47ae586016fb11eb1b5ee1f775005b00f2c030c22fbebffc4c7fb3f4ae5b0032e7ab79b3fa48e17bb576486ba73ada0322577efd52b79f229da7e05d00a215ab3a1d717ede7c383c2eff400c4fd13c2eb6dd9e4165f67a7f5260619e459d7d9e2d276f44839ea1ec8bcc460a94b759b12b49f49ba350dab04313953d9ac0a8ac2fdd2b5cbfc70c62cdfaea658427afdc7a8a86c6a3b85c795364077fab193e87965a2cc45cbc82656e62410f027b79276317d7a1a81ebc721af6174f34e7d524c2b333e9802d2ecebec414bbdecd4587bc15079001ef140d65f689bb8f686cd670376d1e579a23fc5d098137ef2f11ec4413fcc308e689f4fcb11bde15c657651ee82694cdb676a286b2059fdf41210eceb9f03c3add1e316495a613d85e9126f4e4ba4565a2465fe578587748476360e353c2cd0e880100be8821ddae242f54efb4e7079420312443834db98e9252456b97cd1925880fffba64b0fcf2c8c05f49e0739c78df846975d99d8072b7c3c2ed5df96cdc3ad3a5dfb9d9fa8a73154765f33ca68a64bfced57391bd54250d5681aa09c28970f1fad0627205a0ea68e02bba7edb8e4f2468d70c879a585461349637639887d41f3206da7421bba36c142947a5bfa91ed341b466f8f6c8c12af0f2",
	},
	{ //#21
		"0795d80bc7f40f4d41c280271a2e4f7f",
		"ff824c906594aff365d3cb1f",
		"1ad4e74d127f935beee57cff920665babe7ce56227377afe570ba786193ded3412d4812453157f42fafc418c02a746c1232c234a639d49baa8f041c12e2ef540027764568ce49886e0d913e28059a3a485c6eee96337a30b28e4cd5612c2961539fa6bc5de034cbedc5fa15db844013e0bef276e27ca7a4faf47a5c1093bd643354108144454d221b3737e6cb87faac36ed131959babe44af2890cfcc4e23ffa24470e689ce0894f5407bb0c8665cff536008ad2ac6f1c9ef8289abd0bd9b72f21c597bda5210cf928c805af2dd4a464d52e36819d521f967bba5386930ab5b4cf4c71746d7e6e964673457348e9d71d170d9eb560bd4bdb779e610ba816bf776231ebd0af5966f5cdab6815944032ab4dd060ad8dab880549e910f1ffcf6862005432afad",
		"98a47a430d8fd74dc1829a91e3481f8ed024d8ba34c9b903321b04864db333e558ae28653dffb2",
		"598798e51e3b70677ee1cd17c25dd6a4752f42aa51b2d055df9992e46afc8e48ac0e99f645bbab4388bc22bc674ecd3bea4f59dbe77a3e33f1b66d751f2772b59eb462443d2de8f27cbf057b8e00c000e2653a597c440cdd3a87a83f7a2f26f3966ba26fc60c05de7da075e635fdd3b5fefa816398855e099ab746278fc57f65b7573f5372a676ca5a9835d0e158f16201ea16fb6685da1829cffc6cea57a9937e822dc6becd7679239c55df5b88caa91522eeb3223dd9357d374a5b3be015624ca21ff667f427d94e9c5cd6e9ec227d3fb2b8c3835dfe5cd8949da744f8d30470a5f36dc33f3f57586ff9e4f117d94b1d1a94318a7cecb61f0386b2e34d4d39e965640e2fc211f34552352ef1df24f409583f82d4b259bf0f9358c3330bea2a2cab2fd303d8cd22abce5339576d8a6736f46589d8",
	},
	// These cases test non-standard tag sizes.
	{ //#22
		"89c54b0d3bc3c397d5039058c220685f",
		"bc7f45c00868758d62d4bb4d",
		"582670b0baf5540a3775b6615605bd05",
		"48d16cda0337105a50e2ed76fd18e114",
		"6e37e818153f115f2fab4c890f3eac139a3ee8b30bf2cbcb54c39ff0651313",
	},
	{ //#23
		"bad6049678bf75c9087b3e3ae7e72c13",
		"a0a017b83a67d8f1b883e561",
		"a1be93012f05a1958440f74a5311f4a1",
		"f7c27b51d5367161dc2ff1e9e3edc6f2",
		"baa7c826af7983e1824558e7e31d04063543c8a5e80eb58af0e38b7a1581",
	},
	{ //#24
		"66a3c722ccf9709525650973ecc100a9",
		"1621d42d3a6d42a2d2bf9494",
		"61fa9dbbed2190fbc2ffabf5d2ea4ff8",
		"d7a9b6523b8827068a6354a6d166c6b9",
		"4e920aff4744aef585b81c80fe962231d13d8f7f03e56a06cb33d12491",
	},
	{ //#25
		"562ae8aadb8d23e0f271a99a7d1bd4d1",
		"f7a5e2399413b89b6ad31aff",
		"bbdc3504d803682aa08a773cde5f231a",
		"2b9680b886b3efb7c6354b38c63b5373",
		"716a4e0150125a51e72f95d900814fc37b0ddba2a85bda1f8819b774",
	},
	{ //#26
		"11754cd72aec309bf52f7687212e8957",
		"",
		"",
		"",
		"250327c674aaf477aef2675748cf6971",
	},
	{ // https://tools.ietf.org/html/rfc8998 A.1. SM4-GCM Test Vectors
		"0123456789abcdeffedcba9876543210",
		"00001234567800000000abcd",
		"aaaaaaaaaaaaaaaabbbbbbbbbbbbbbbbccccccccccccccccddddddddddddddddeeeeeeeeeeeeeeeeffffffffffffffffeeeeeeeeeeeeeeeeaaaaaaaaaaaaaaaa",
		"feedfacedeadbeeffeedfacedeadbeefabaddad2",
		"17f399f08c67d5ee19d0dc9969c4bb7d5fd46fd3756489069157b282bb200735d82710ca5c22f0ccfa7cbf93d496ac15a56834cbcf98c397b4024a2691233b8d83de3541e4c2b58177e065a9bf7b62ec",
	},
}

func TestSM4GCM(t *testing.T) {
	for i, test := range sm4GCMTests {
		key, _ := hex.DecodeString(test.key)
		c, err := sm4.NewCipher(key)
		if err != nil {
			t.Fatal(err)
		}

		nonce, _ := hex.DecodeString(test.nonce)
		plaintext, _ := hex.DecodeString(test.plaintext)
		ad, _ := hex.DecodeString(test.ad)
		tagSize := (len(test.result) - len(test.plaintext)) / 2

		var sm4gcm cipher.AEAD
		switch {
		// Handle non-standard tag sizes
		case tagSize != 16:
			sm4gcm, err = cipher.NewGCMWithTagSize(c, tagSize)
			if err != nil {
				t.Fatal(err)
			}

		// Handle 0 nonce size (expect error and continue)
		case len(nonce) == 0:
			_, err = cipher.NewGCMWithNonceSize(c, 0)
			if err == nil {
				t.Fatal("expected error for zero nonce size")
			}
			continue

		// Handle non-standard nonce sizes
		case len(nonce) != 12:
			sm4gcm, err = cipher.NewGCMWithNonceSize(c, len(nonce))
			if err != nil {
				t.Fatal(err)
			}

		default:
			sm4gcm, err = cipher.NewGCM(c)
			if err != nil {
				t.Fatal(err)
			}
		}

		ct := sm4gcm.Seal(nil, nonce, plaintext, ad)
		if ctHex := hex.EncodeToString(ct); ctHex != test.result {
			t.Errorf("#%d: got %s, want %s", i, ctHex, test.result)
			continue
		}

		plaintext2, err := sm4gcm.Open(nil, nonce, ct, ad)
		if err != nil {
			t.Errorf("#%d: Open failed", i)
			continue
		}

		if !bytes.Equal(plaintext, plaintext2) {
			t.Errorf("#%d: plaintext's don't match: got %x vs %x", i, plaintext2, plaintext)
			continue
		}

		if len(ad) > 0 {
			ad[0] ^= 0x80
			if _, err := sm4gcm.Open(nil, nonce, ct, ad); err == nil {
				t.Errorf("#%d: Open was successful after altering additional data", i)
			}
			ad[0] ^= 0x80
		}

		nonce[0] ^= 0x80
		if _, err := sm4gcm.Open(nil, nonce, ct, ad); err == nil {
			t.Errorf("#%d: Open was successful after altering nonce", i)
		}
		nonce[0] ^= 0x80

		ct[0] ^= 0x80
		if _, err := sm4gcm.Open(nil, nonce, ct, ad); err == nil {
			t.Errorf("#%d: Open was successful after altering ciphertext", i)
		}
		ct[0] ^= 0x80
	}
}

func TestGCMInvalidTagSize(t *testing.T) {
	key, _ := hex.DecodeString("ab72c77b97cb5fe9a382d9fe81ffdbed")

	c, _ := sm4.NewCipher(key)

	for _, tagSize := range []int{0, 1, c.BlockSize() + 1} {
		aesgcm, err := cipher.NewGCMWithTagSize(c, tagSize)
		if aesgcm != nil || err == nil {
			t.Fatalf("NewGCMWithNonceAndTagSize was successful with an invalid %d-byte tag size", tagSize)
		}
	}
}

func TestTagFailureOverwrite(t *testing.T) {
	// The AESNI GCM code decrypts and authenticates concurrently and so
	// overwrites the output buffer before checking the authentication tag.
	// In order to be consistent across platforms, all implementations
	// should do this and this test checks that.

	key, _ := hex.DecodeString("ab72c77b97cb5fe9a382d9fe81ffdbed")
	nonce, _ := hex.DecodeString("54cc7dc2c37ec006bcc6d1db")
	ciphertext, _ := hex.DecodeString("0e1bde206a07a9c2c1b65300f8c649972b4401346697138c7a4891ee59867d0c")

	c, _ := sm4.NewCipher(key)
	sm4gcm, _ := cipher.NewGCM(c)

	dst := make([]byte, len(ciphertext)-16)
	for i := range dst {
		dst[i] = 42
	}

	result, err := sm4gcm.Open(dst[:0], nonce, ciphertext, nil)
	if err == nil {
		t.Fatal("Bad Open still resulted in nil error.")
	}

	if result != nil {
		t.Fatal("Failed Open returned non-nil result.")
	}

	for i := range dst {
		if dst[i] != 0 {
			t.Fatal("Failed Open didn't zero dst buffer")
		}
	}
}

func TestGCMCounterWrap(t *testing.T) {
	// Test that the last 32-bits of the counter wrap correctly.
	tests := []struct {
		nonce, tag string
	}{
		{"0fa72e25", "07d6369bf22b6507a736f19972b5a0e3"},   // counter: 7eb59e4d961dad0dfdd75aaffffffff0
		{"afe05cc1", "36e0538ec7fda19fc98621f3de9de166"},   // counter: 75d492a7e6e6bfc979ad3a8ffffffff4
		{"9ffecbef", "aac0fd90f5acaf9db1412d059bfedd92"},   // counter: c8bb108b0ecdc71747b9d57ffffffff5
		{"ffc3e5b3", "10e9b0f8088e320a75c4512f2bcfa5fd"},   // counter: 706414d2de9b36ab3b900a9ffffffff6
		{"cfdd729d", "afee327e47b1d4e7c6da27a0fdde1544"},   // counter: cd0b96fe36b04e750584e56ffffffff7
		{"010ae3d486", "ecc0e9cc4a92aa4804a5fd6a909eec7d"}, // counter: e36c18e69406c49722808104fffffff8
		{"01b1107a9d", "27785ab3613dd235e2daa8d3244e7869"}, // counter: e6d56eaf9127912b6d62c6dcffffffff
	}
	key, err := sm4.NewCipher(make([]byte, 16))
	if err != nil {
		t.Fatal(err)
	}
	plaintext := make([]byte, 16*17+1)
	for i, test := range tests {
		nonce, _ := hex.DecodeString(test.nonce)
		want, _ := hex.DecodeString(test.tag)
		aead, err := cipher.NewGCMWithNonceSize(key, len(nonce))
		if err != nil {
			t.Fatal(err)
		}
		got := aead.Seal(nil, nonce, plaintext, nil)
		if !bytes.Equal(got[len(plaintext):], want) {
			t.Errorf("test[%v]: got: %x, want: %x", i, got[len(plaintext):], want)
		}
		_, err = aead.Open(nil, nonce, got, nil)
		if err != nil {
			t.Errorf("test[%v]: authentication failed", i)
		}
	}
}

func TestSM4GCMRandom(t *testing.T) {
	key := []byte("0123456789ABCDEF")
	nonce := []byte("0123456789AB")
	plaintext := make([]byte, 464)
	
	io.ReadFull(rand.Reader, plaintext)
	c, err := sm4.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	aead, err := cipher.NewGCMWithNonceSize(c, len(nonce))
	if err != nil {
		t.Fatal(err)
	}
	got := aead.Seal(nil, nonce, plaintext, nil)

	result, err := aead.Open(nil, nonce, got, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(result, plaintext) {
		t.Error("gcm seal/open 464 bytes fail")
	}
}
