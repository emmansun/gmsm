package sm3

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"hash"
	"io"
	"math/big"
	"reflect"
	"testing"

	"github.com/emmansun/gmsm/internal/cryptotest"
	"github.com/emmansun/gmsm/internal/cpu"
)

type sm3Test struct {
	out       string
	in        string
	halfState string // marshaled hash state after first half of in written, used by TestGoldenMarshal
}

var golden = []sm3Test{
	{"66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0", "abc", "sm3\x03s\x80\x16oI\x14\xb2\xb9\x17$B\xd7ڊ\x06\x00\xa9o0\xbc\x1618\xaa\xe3\x8d\xeeM\xb0\xfb\x0eNa\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01"},
	{"debe9ff92275b8a138604889c18e5a4d6fdb70e5387e5765293dcba39c0c5732", "abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd", "sm3\x03s\x80\x16oI\x14\xb2\xb9\x17$B\xd7ڊ\x06\x00\xa9o0\xbc\x1618\xaa\xe3\x8d\xeeM\xb0\xfb\x0eNabcdabcdabcdabcdabcdabcdabcdabcd\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00 "},
	{"952eb84cacee9c10bde4d6882d29d63140ba72af6fe485085095dccd5b872453", "abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabc", "sm3\x03s\x80\x16oI\x14\xb2\xb9\x17$B\xd7ڊ\x06\x00\xa9o0\xbc\x1618\xaa\xe3\x8d\xeeM\xb0\xfb\x0eNabcdabcdabcdabcdabcdabcdabcdabcda\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00!"},
	{"90d52a2e85631a8d6035262626941fa11b85ce570cec1e3e991e2dd7ed258148", "abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd", "sm3\x03YPށF\x86d\xebB\xfdL\x86\x1e|\xa0\n\xc0\xa5\x91\v\xae\x9aU\xea\x1aۍ\x17v<\xa2\"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00@"},
	{"e1c53f367a9c5d19ab6ddd30248a7dafcc607e74e6bcfa52b00e0ba35e470421", "abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabc", "sm3\x03YPށF\x86d\xebB\xfdL\x86\x1e|\xa0\n\xc0\xa5\x91\v\xae\x9aU\xea\x1aۍ\x17v<\xa2\"a\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00A"},
	{"520472cafdaf21d994c5849492ba802459472b5206503389fc81ff73adbec1b4", "abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabc", "sm3\x03\x89\xf7\x9c\x9fZ\xd5\xed\x15\x10x\xd3\xd9\xecK\x89\xb1\xa5q\xc5K\xdb\xcf\xc1\xb9Y\x13s\xb2\x82\x9f\xf9\vabc\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x83"},
}

func TestGolden(t *testing.T) {
	for i := 0; i < len(golden); i++ {
		g := golden[i]
		h := Sum([]byte(g.in))
		s := fmt.Sprintf("%x", h)
		fmt.Printf("%s\n", base64.StdEncoding.EncodeToString(h[:]))
		if s != g.out {
			t.Fatalf("SM3 function: sm3(%s) = %s want %s", g.in, s, g.out)
		}
		c := New()
		for j := 0; j < 3; j++ {
			if j < 2 {
				io.WriteString(c, g.in)
			} else {
				io.WriteString(c, g.in[0:len(g.in)/2])
				c.Sum(nil)
				io.WriteString(c, g.in[len(g.in)/2:])
			}
			s := fmt.Sprintf("%x", c.Sum(nil))
			if s != g.out {
				t.Fatalf("sm3[%d](%s) = %s want %s", j, g.in, s, g.out)
			}
			c.Reset()
		}
	}
}

func TestGoldenMarshal(t *testing.T) {
	tests := []struct {
		name    string
		newHash func() hash.Hash
		gold    []sm3Test
	}{
		{"", New, golden},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for _, g := range tt.gold {
				h := tt.newHash()
				h2 := tt.newHash()

				io.WriteString(h, g.in[:len(g.in)/2])

				state, err := h.(encoding.BinaryMarshaler).MarshalBinary()
				if err != nil {
					t.Errorf("could not marshal: %v", err)
					continue
				}

				if string(state) != g.halfState {
					t.Errorf("sm3%s(%q) state = %q, want %q", tt.name, g.in, state, g.halfState)
					continue
				}

				if err := h2.(encoding.BinaryUnmarshaler).UnmarshalBinary(state); err != nil {
					t.Errorf("could not unmarshal: %v", err)
					continue
				}

				io.WriteString(h, g.in[len(g.in)/2:])
				io.WriteString(h2, g.in[len(g.in)/2:])

				if actual, actual2 := h.Sum(nil), h2.Sum(nil); !bytes.Equal(actual, actual2) {
					t.Errorf("sm3%s(%q) = 0x%x != marshaled 0x%x", tt.name, g.in, actual, actual2)
				}
			}
		})
	}
}

var sm3TestVector = []struct {
	out string
	in  string
}{
	// Test vectors from Crypto++
	{
		"1ab21d8355cfa17f8e61194831e81a8f22bec8c728fefb747ed035eb5082aa2b",
		"",
	},
	{
		"82ec580fe6d36ae4f81cae3c73f4a5b3b5a09c943172dc9053c69fd8e18dca1e",
		"61626364",
	},
	{
		"b58b85b795b34879c354428f7c78cd1486c4ef25ea4c5d68e611ff41c15731ef",
		"6162636461626364",
	},
	{
		"fd959b2560dadd0c0839144be6090cb665915156179c1fa6dc00292da7a2b9c2",
		"616263646162636461626364",
	},
	{
		"639c6f6b30d93ecebd559a953ba2eb72705db7d2be82bbf32979380e02124971",
		"61626364616263646162636461626364",
	},
	{
		"3f0371287a1d1fd198e12bba07e94ae5815dc7e06ba45856b6e53e56f1594f23",
		"6162636461626364616263646162636461626364",
	},
	{
		"8d15c0b9e7540b5f41b359774127ee51d126a3c780357336c7d39d6ffc01f130",
		"616263646162636461626364616263646162636461626364",
	},
	{
		"0a5a2fafba54c2a6593b18c5877c50c26bee5369bc7f07b0c66a641e49295419",
		"61626364616263646162636461626364616263646162636461626364",
	},
	{
		"73edef5c9d3710f14dbaf892f50ce9dfab48e462d837d93ec0f9422c5f2a4007",
		"6162636461626364616263646162636461626364616263646162636461626364",
	},
	{
		"28a6a907842a5b4a360cead2ff6f0b96f1b28c12e5c9ed0be58169c26863b0d8",
		"616263646162636461626364616263646162636461626364616263646162636461626364",
	},
	{
		"035be9acd343d3711a61972ea6a80d4deb38e40c901f1cd20786cf57c82ce8ed",
		"61626364616263646162636461626364616263646162636461626364616263646162636461626364",
	},
	{
		"7a04f699def87c0ef8a9dd44d46a71a39e6b594bc467298d04454e52aa922dca",
		"6162636461626364616263646162636461626364616263646162636461626364616263646162636461626364",
	},
	{
		"6fe77b627c1a12bc367d13c8f07b32ffbde1a537b1b9cb061bf7d75a692e02bb",
		"616263646162636461626364616263646162636461626364616263646162636461626364616263646162636461626364",
	},
	{
		"4251f280685451d9f73d75e6d59f4e3f140f3a0b22f9cb0416e4dd15c1410d11",
		"61626364616263646162636461626364616263646162636461626364616263646162636461626364616263646162636461626364",
	},
	{
		"9a032f0cf27e4b408f252452d451cac51a422d43ae73ab6cd7ec2483241358e9",
		"6162636461626364616263646162636461626364616263646162636461626364616263646162636461626364616263646162636461626364",
	},
	{
		"7b0685c88114bee154296c262d619a3d43c4fbf325d5dcb6f2bbdbf96d4275db",
		"616263646162636461626364616263646162636461626364616263646162636461626364616263646162636461626364616263646162636461626364",
	},
	{
		"debe9ff92275b8a138604889c18e5a4d6fdb70e5387e5765293dcba39c0c5732",
		"61626364616263646162636461626364616263646162636461626364616263646162636461626364616263646162636461626364616263646162636461626364",
	},
	{
		"860f7ad118996a6f631c5e4ac693157aefda97a18a873d3323f64c28a8a44fc5",
		"6162636461626364616263646162636461626364616263646162636461626364616263646162636461626364616263646162636461626364616263646162636461626364",
	},
	{
		"0c5e778ef656184f8c9ee54f0fe0c9ce5059e02c771325184619be82c92a8c5a",
		"616263646162636461626364616263646162636461626364616263646162636461626364616263646162636461626364616263646162636461626364616263646162636461626364",
	},
	{
		"bb78eaeb6b00d13d43ab682b8d65512aa9e91fbc8c6c2841c6b96345f44f9652",
		"61626364616263646162636461626364616263646162636461626364616263646162636461626364616263646162636461626364616263646162636461626364616263646162636461626364",
	},
	{
		"716f5396cc9312609c28c645344ec695fdabdb9fbf11de36c1b33ac5291cca6c",
		"6162636461626364616263646162636461626364616263646162636461626364616263646162636461626364616263646162636461626364616263646162636461626364616263646162636461626364",
	},
	{
		"24ce4fbaab353814f890561cbde3d10308c33ac6831ff74e236e8e0525b2cd4e",
		"616263646162636461626364616263646162636461626364616263646162636461626364616263646162636461626364616263646162636461626364616263646162636461626364616263646162636461626364",
	},
	{
		"5852844cbc2d742d4b129392646b3a1029c54f9813eec409012bf2c4bf0acdeb",
		"61626364616263646162636461626364616263646162636461626364616263646162636461626364616263646162636461626364616263646162636461626364616263646162636461626364616263646162636461626364",
	},
	{
		"3efb9d84992a87607dc43d91fb818cdbebe3f6cfac66456495f6cb922f9c2fb3",
		"6162636461626364616263646162636461626364616263646162636461626364616263646162636461626364616263646162636461626364616263646162636461626364616263646162636461626364616263646162636461626364",
	},
	{
		"994bf36eb6c0099b21d6ead2cf71490ea57aa845f0feed97d7f8ce2788e22342",
		"616263646162636461626364616263646162636461626364616263646162636461626364616263646162636461626364616263646162636461626364616263646162636461626364616263646162636461626364616263646162636461626364",
	},
	// Test vectors from GmSSL
	{
		"2b6173f01b9002cac00ec91c8b481867c2e35bf408bde154d62844da1b5b6e18",
		"8f",
	},
	{
		"b49515e07f9e777070d725fd49d41579d263cffb4ec3fa65b93c87b473d91cb9",
		"bf23",
	},
	{
		"171e937ace4b4e18fef1efbae2feaaa7f1022f722ffc82155a24e75ae4ac4b29",
		"7a9719",
	},
	{
		"041326870d40091c58ce7a252458e86cf19664ca6aa7e11db8952329b7688a1c",
		"fb39e8cc",
	},
	{
		"b2249a453544ca8699e07b369382001e8d741c76cad673851a4a25be5c1765cd",
		"95aaf89fe9",
	},
	{
		"5ac22e272e9c6e7cef2c17178302817d865cb178c6c04b331b0e5ee61c2014f9",
		"7688740e973d",
	},
	{
		"667509d27e794d11621817e993b8da4accacb3f83a719e635e0ea455905040de",
		"d7b976b5f139c5",
	},
	{
		"911b051b02636a5efe12ec8fafa3b18d55b1aa6c4bc9e07789b2d44470b94167",
		"391b4861669a3de0",
	},
	{
		"429debaa692b6aeb85aae6666ed2f8c206395d6a87560699dca23d6035918b28",
		"e71ec750cc768837a8",
	},
	{
		"140f2130d810310c5d0a988e9b380678031c4a9050aabe1a7b5603a98f452684",
		"898fb851bb90bceefb6d",
	},
	{
		"3b4c28a7bd3ab41b65525f580edcbe1a308c3fa09d821c192858a349581ca55b",
		"7d33665e8ef4f522b55df7",
	},
	{
		"ecc8181aaffc4dbce05c8ad2b3544bf6838791d6c9966de2996318b33ee37b8b",
		"815e16c63b984946c07ad55a",
	},
	{
		"5b617c321f8769b5227bc02471c117f44dfdf816ebabb60575d07edef1f880c0",
		"87eb36f4116f4d2aa05c9d2b56",
	},
	{
		"911048c7853c404970a9230fd997a95b5b4a00ff74a8aafbbce72b4f9444de8f",
		"f670d1ed03316874263b039cb53a",
	},
	{
		"ddc82e25eb0caa33ee7229a12ac69a7b9b72345236e835857e81bd2173edc532",
		"102cb525fa7e0de28efe6d2f2ad1b1",
	},
	{
		"ad2b435cda7615f0ac367aeca843a69189b665552233f4804439090f86f3009f",
		"74c2e33d49e8c2a5144e82edc04218f9",
	},
	{
		"78b026963e21183970483449ee9272a877a2254c89c63f0f6a0b4b86dea1db33",
		"706c9721e103771b688e97636ab26b412c",
	},
	{
		"eb46d32b15ebf5c5fd2af316c9717065cc21376053945f04cb6f92d31e1666e9",
		"ac24ded9e54844b3e0ca037ec1d0f8103fec",
	},
	{
		"c1761751af06a5be5233bd7a8d6fc497fc1ea3f36cafb988e457f281615bf867",
		"1b39c5a77a7cd6d538c3d2d1079f3f5338c620",
	},
	{
		"7239694c9b61cdf9e62d5d48bafdc283f2041a9c0845e0dd975bb3a8e5a01198",
		"65a647b8dd26dcaece299788b13ac05a0e71c577",
	},
	{
		"6b70357406f59521ba34f961aa4c7d78a088db325595d6267af5d499f1d95b1f",
		"98f13468ff3c69382495d34ba12e1e4bd895bec29a",
	},
	{
		"d98dea9c0a614fb689750c75fd4c6d5e91447104f8f563dbea1f50602da018f5",
		"03de8240c26bbaef801d579d2f2be849ffeab779e056",
	},
	{
		"acfaaad49a8b94d1df81ea951a30ee2b899fba79f60c452f63af3c79e1283944",
		"a733f4adfbe6b110c1ef6fd3599b680a6fa5644fbcd073",
	},
	{
		"1ec1f230391a74818cf79b24c9b4df63f0a291e317eed70990c65efad9b5ad33",
		"1cb083e53c6242d1dd62510ccfb3d5496d692b8017023bae",
	},
	{
		"9aa7e33e6d4edc5e487a4a15b9bfa013d167d256afd86df7770468107df19f87",
		"6a8000baf113ddee93437ce36c9b28f69f0df4a0500633eeab",
	},
	{
		"6f5321a4bd11eb49dcfc9214d1391fcb733bedca2148f05a18afcc3d141211e6",
		"d2d424446f9b2b29efcf93f2da96208a90a39fb0dc7e46ad8f53",
	},
	{
		"6194eeda953c297c20ec9876e4f0d51c44c1ccc4037cc90e6ba184572c84ef2f",
		"db1bcaf89851cbcc847347eb4b1d0c40ea6f3e0de1853d713704bc",
	},
	{
		"e715a625d3d1271f8a3aadcf215f91161c1bc161bd645627b78c707f0c8b3b3f",
		"bab74a186887702204977bceefb1bba1d52c9c58667e7fe0e3f4bc19",
	},
	{
		"4c77eb46a03cc08c37ee567127c0bce8f952ba5fdd729ff6fc44e3ffe307a507",
		"36cdc511b3082afd547f4331298f879aa742c634c10e0263f80efdeece",
	},
	{
		"6a1ad547946c39bb22dda3dc8b861010790d8cebf4cf8dc3c9493ca8d4c92f70",
		"072bedbcbe5f9295ec6a2bf22490d984bc7388fe99035916c1262e8b592c",
	},
	{
		"8abe85411e3ce2c2a2e582eda291d45fcd3a4a5cd7e1851a7e67a49fa2f3ba9a",
		"6009dced63eef9985da162f1beda1b56e0c17d51119b1aaeee7b28050bd1dd",
	},
	{
		"355422a0c526088b16c5207d1adad939cf9642150ebe110e213f23884f8db789",
		"45dc649b6c57a9e21e9b069d06e12729b80a62facd901c6e9ed10c38ba5c2e65",
	},
	{
		"d730e1a1482889c9f4f2b661941c2e1ea6a12f1c78e70908df164b33c6226dee",
		"8d8ac08987feb09407263bc7cd471911372f1daebe2c879b258c0efbef9c544aba",
	},
}

func TestSM3Hash(t *testing.T) {
	for i, tt := range sm3TestVector {
		input, _ := hex.DecodeString(tt.in)
		res := Sum(input)
		if hex.EncodeToString(res[:]) != tt.out {
			t.Errorf("case %v failed, in: %v ", i, tt.in)
		}
	}
	t.Run("SM3", func(t *testing.T) {
		cryptotest.TestHash(t, New)
	})
}

func TestSize(t *testing.T) {
	c := New()
	if got := c.Size(); got != Size {
		t.Errorf("Size = %d; want %d", got, Size)
	}
}

func TestBlockSize(t *testing.T) {
	c := New()
	if got := c.BlockSize(); got != BlockSize {
		t.Errorf("BlockSize = %d want %d", got, BlockSize)
	}
	fmt.Printf("ARM64 has sm3 %v, has sm4 %v, has aes %v\n", cpu.ARM64.HasSM3, cpu.ARM64.HasSM4, cpu.ARM64.HasAES)
}

// Tests that blockGeneric (pure Go) and block (in assembly for some architectures) match.
func TestBlockGeneric(t *testing.T) {
	gen, asm := New().(*digest), New().(*digest)
	buf := make([]byte, BlockSize*20) // arbitrary factor
	rand.Read(buf)
	blockGeneric(gen, buf)
	block(asm, buf)
	if *gen != *asm {
		t.Error("block and blockGeneric resulted in different states")
	}
}

func TestAllocations(t *testing.T) {
	in := []byte("hello, world!")
	out := make([]byte, 0, Size)
	h := New()
	n := int(testing.AllocsPerRun(10, func() {
		h.Reset()
		h.Write(in)
		out = h.Sum(out[:0])
	}))
	if n > 0 {
		t.Errorf("allocs = %d, want 0", n)
	}
}

var bench = New()
var benchSH256 = sha256.New()
var buf = make([]byte, 8192)

func benchmarkSize(hash hash.Hash, b *testing.B, size int) {
	b.SetBytes(int64(size))
	sum := make([]byte, bench.Size())
	for i := 0; i < b.N; i++ {
		hash.Reset()
		hash.Write(buf[:size])
		hash.Sum(sum[:0])
	}
}

func BenchmarkHash8Bytes(b *testing.B) {
	benchmarkSize(bench, b, 8)
}

func BenchmarkHash8Bytes_SH256(b *testing.B) {
	benchmarkSize(benchSH256, b, 8)
}

func BenchmarkHash1K(b *testing.B) {
	benchmarkSize(bench, b, 1024)
}

func BenchmarkHash1K_SH256(b *testing.B) {
	benchmarkSize(benchSH256, b, 1024)
}

func BenchmarkHash8K(b *testing.B) {
	benchmarkSize(bench, b, 8192)
}

func BenchmarkHash8K_SH256(b *testing.B) {
	benchmarkSize(benchSH256, b, 8192)
}

func TestKdf(t *testing.T) {
	type args struct {
		z   []byte
		len int
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{"sm3 case 1", args{[]byte("emmansun"), 16}, "708993ef1388a0ae4245a19bb6c02554"},
		{"sm3 case 2", args{[]byte("emmansun"), 32}, "708993ef1388a0ae4245a19bb6c02554c632633e356ddb989beb804fda96cfd4"},
		{"sm3 case 3", args{[]byte("emmansun"), 48}, "708993ef1388a0ae4245a19bb6c02554c632633e356ddb989beb804fda96cfd47eba4fa460e7b277bc6b4ce4d07ed493"},
		{"sm3 case 4", args{[]byte("708993ef1388a0ae4245a19bb6c02554c632633e356ddb989beb804fda96cfd47eba4fa460e7b277bc6b4ce4d07ed493708993ef1388a0ae4245a19bb6c02554c632633e356ddb989beb804fda96cfd47eba4fa460e7b277bc6b4ce4d07ed493"), 48}, "49cf14649f324a07e0d5bb2a00f7f05d5f5bdd6d14dff028e071327ec031104590eddb18f98b763e18bf382ff7c3875f"},
		{"sm3 case 5", args{[]byte("708993ef1388a0ae4245a19bb6c02554c632633e356ddb989beb804fda96cfd47eba4fa460e7b277bc6b4ce4d07ed493708993ef1388a0ae4245a19bb6c02554c632633e356ddb989beb804fda96cfd47eba4fa460e7b277bc6b4ce4d07ed493"), 121}, "49cf14649f324a07e0d5bb2a00f7f05d5f5bdd6d14dff028e071327ec031104590eddb18f98b763e18bf382ff7c3875f30277f3179baebd795e7853fa643fdf280d8d7b81a2ab7829f615e132ab376d32194cd315908d27090e1180ce442d9be99322523db5bfac40ac5acb03550f5c93e5b01b1d71f263086"},
		{"sm3 case 6", args{[]byte("708993ef1388a0ae4245a19bb6c02554c632633e356ddb989beb804fda96cfd47eba4fa460e7b277bc6b4ce4d07ed493708993ef1388a0ae4245a19bb6c02554c632633e356ddb989beb804fda96cfd47eba4fa460e7b277bc6b4ce4d07ed493"), 128}, "49cf14649f324a07e0d5bb2a00f7f05d5f5bdd6d14dff028e071327ec031104590eddb18f98b763e18bf382ff7c3875f30277f3179baebd795e7853fa643fdf280d8d7b81a2ab7829f615e132ab376d32194cd315908d27090e1180ce442d9be99322523db5bfac40ac5acb03550f5c93e5b01b1d71f2630868909a6a1250edb"},
		{"sm3 case 7", args{[]byte("708993ef1388a0ae4245a19bb6c02554c632633e356ddb989beb804fda96cfd47eba4fa460e7b277bc6b4ce4d07ed493708993ef1388a0ae4245a19bb6c02554c632633e356ddb989beb804fda96cfd47eba4fa460e7b277bc6b4ce4d07ed493"), 159}, "49cf14649f324a07e0d5bb2a00f7f05d5f5bdd6d14dff028e071327ec031104590eddb18f98b763e18bf382ff7c3875f30277f3179baebd795e7853fa643fdf280d8d7b81a2ab7829f615e132ab376d32194cd315908d27090e1180ce442d9be99322523db5bfac40ac5acb03550f5c93e5b01b1d71f2630868909a6a1250edb9abb2c6b0673e349f64c6577d4ba1b0a9c360016bae9478f8a80d5426327e8"},
		{"sm3 case 8", args{[]byte("708993ef1388a0ae4245a19bb6c02554c632633e356ddb989beb804fda96cfd47eba4fa460e7b277bc6b4ce4d07ed493708993ef1388a0ae4245a19bb6c02554c632633e356ddb989beb804fda96cfd47eba4fa460e7b277bc6b4ce4d07ed493"), 250}, "49cf14649f324a07e0d5bb2a00f7f05d5f5bdd6d14dff028e071327ec031104590eddb18f98b763e18bf382ff7c3875f30277f3179baebd795e7853fa643fdf280d8d7b81a2ab7829f615e132ab376d32194cd315908d27090e1180ce442d9be99322523db5bfac40ac5acb03550f5c93e5b01b1d71f2630868909a6a1250edb9abb2c6b0673e349f64c6577d4ba1b0a9c360016bae9478f8a80d5426327e84ea915c10ef39a016618b00aaae8735a8a1405180746ddd7ccd05dc890c5e5d07f49c40afdbc09267859ac5967b8c1163dc6defab955604e45e349a51df11d81b298424b84472607249a05b481ae88d98a9273ecdee009add06196"},
		{"sm3 case 9", args{[]byte("708993ef1388a0ae4245a19bb6c02554c632633e356ddb989beb804fda96cfd47eba4fa460e7b277bc6b4ce4d07ed493708993ef1388a0ae4245a19bb6c02554c632633e356ddb989beb804fda96cfd47eba4fa460e7b277bc6b4ce4d07ed493"), 256}, "49cf14649f324a07e0d5bb2a00f7f05d5f5bdd6d14dff028e071327ec031104590eddb18f98b763e18bf382ff7c3875f30277f3179baebd795e7853fa643fdf280d8d7b81a2ab7829f615e132ab376d32194cd315908d27090e1180ce442d9be99322523db5bfac40ac5acb03550f5c93e5b01b1d71f2630868909a6a1250edb9abb2c6b0673e349f64c6577d4ba1b0a9c360016bae9478f8a80d5426327e84ea915c10ef39a016618b00aaae8735a8a1405180746ddd7ccd05dc890c5e5d07f49c40afdbc09267859ac5967b8c1163dc6defab955604e45e349a51df11d81b298424b84472607249a05b481ae88d98a9273ecdee009add0619641bd7d9f0b13"},
		{"sm3 case 10", args{[]byte("708993ef1388a0ae4245a19bb6c02554c632633e356ddb989beb804fda96cfd47eba4fa460e7b277bc6b4ce4d07ed493708993ef1388a0ae4245a19bb6c02554c632633e356ddb989beb804fda96cfd47eba4fa460e7b277bc6b4ce4d07ed493"), 257}, "49cf14649f324a07e0d5bb2a00f7f05d5f5bdd6d14dff028e071327ec031104590eddb18f98b763e18bf382ff7c3875f30277f3179baebd795e7853fa643fdf280d8d7b81a2ab7829f615e132ab376d32194cd315908d27090e1180ce442d9be99322523db5bfac40ac5acb03550f5c93e5b01b1d71f2630868909a6a1250edb9abb2c6b0673e349f64c6577d4ba1b0a9c360016bae9478f8a80d5426327e84ea915c10ef39a016618b00aaae8735a8a1405180746ddd7ccd05dc890c5e5d07f49c40afdbc09267859ac5967b8c1163dc6defab955604e45e349a51df11d81b298424b84472607249a05b481ae88d98a9273ecdee009add0619641bd7d9f0b13a5"},
		{"sm3 case 11", args{[]byte("708993ef1388a0ae4245a19bb6c02554c632633e356ddb989beb804fda96cfd47eba4fa460e7b277bc6b4ce4d07ed493708993ef1388a0ae4245a19bb6c02554c632633e356ddb989beb804fda96cfd47eba4fa460e7b277bc6b4ce4d07ed493"), 300}, "49cf14649f324a07e0d5bb2a00f7f05d5f5bdd6d14dff028e071327ec031104590eddb18f98b763e18bf382ff7c3875f30277f3179baebd795e7853fa643fdf280d8d7b81a2ab7829f615e132ab376d32194cd315908d27090e1180ce442d9be99322523db5bfac40ac5acb03550f5c93e5b01b1d71f2630868909a6a1250edb9abb2c6b0673e349f64c6577d4ba1b0a9c360016bae9478f8a80d5426327e84ea915c10ef39a016618b00aaae8735a8a1405180746ddd7ccd05dc890c5e5d07f49c40afdbc09267859ac5967b8c1163dc6defab955604e45e349a51df11d81b298424b84472607249a05b481ae88d98a9273ecdee009add0619641bd7d9f0b13a502e36e67b5836d0480a518a01046fa2738698fbe5e5008de11704b45531532667896158158ea08847a55a9"},
		{"sm3 case 12", args{[]byte("708993ef1388a0ae4245a19bb6c02554c632633e356ddb989beb804fda96cfd47eba4fa460e7b277bc6b4ce4d07ed493708993ef1388a0ae4245a19bb6c02554c632633e356ddb989beb804fda96cfd47eba4fa460e7b277bc6b4ce4d07ed493"), 383}, "49cf14649f324a07e0d5bb2a00f7f05d5f5bdd6d14dff028e071327ec031104590eddb18f98b763e18bf382ff7c3875f30277f3179baebd795e7853fa643fdf280d8d7b81a2ab7829f615e132ab376d32194cd315908d27090e1180ce442d9be99322523db5bfac40ac5acb03550f5c93e5b01b1d71f2630868909a6a1250edb9abb2c6b0673e349f64c6577d4ba1b0a9c360016bae9478f8a80d5426327e84ea915c10ef39a016618b00aaae8735a8a1405180746ddd7ccd05dc890c5e5d07f49c40afdbc09267859ac5967b8c1163dc6defab955604e45e349a51df11d81b298424b84472607249a05b481ae88d98a9273ecdee009add0619641bd7d9f0b13a502e36e67b5836d0480a518a01046fa2738698fbe5e5008de11704b45531532667896158158ea08847a55a93f26fd6c99111b3017db1d1e6025d28d88ed3a419eb9c72e4fa3267f19c806092fd80cb91079cc00cefc55db53ad840ed1e6384f4cf02d9f2ecbaed54391e7a6da71fca4ea53ccfdd4d85adf37e4be8af1324f"},
		{"sm3 case 13", args{[]byte("708993ef1388a0ae4245a19bb6c02554c632633e356ddb989beb804fda96cfd47eba4fa460e7b277bc6b4ce4d07ed493708993ef1388a0ae4245a19bb6c02554c632633e356ddb989beb804fda96cfd47eba4fa460e7b277bc6b4ce4d07ed493"), 384}, "49cf14649f324a07e0d5bb2a00f7f05d5f5bdd6d14dff028e071327ec031104590eddb18f98b763e18bf382ff7c3875f30277f3179baebd795e7853fa643fdf280d8d7b81a2ab7829f615e132ab376d32194cd315908d27090e1180ce442d9be99322523db5bfac40ac5acb03550f5c93e5b01b1d71f2630868909a6a1250edb9abb2c6b0673e349f64c6577d4ba1b0a9c360016bae9478f8a80d5426327e84ea915c10ef39a016618b00aaae8735a8a1405180746ddd7ccd05dc890c5e5d07f49c40afdbc09267859ac5967b8c1163dc6defab955604e45e349a51df11d81b298424b84472607249a05b481ae88d98a9273ecdee009add0619641bd7d9f0b13a502e36e67b5836d0480a518a01046fa2738698fbe5e5008de11704b45531532667896158158ea08847a55a93f26fd6c99111b3017db1d1e6025d28d88ed3a419eb9c72e4fa3267f19c806092fd80cb91079cc00cefc55db53ad840ed1e6384f4cf02d9f2ecbaed54391e7a6da71fca4ea53ccfdd4d85adf37e4be8af1324f43"},
		{"sm3 case 14", args{[]byte("708993ef1388a0ae4245a19bb6c02554c632633e356ddb989beb804fda96cfd47eba4fa460e7b277bc6b4ce4d07ed493708993ef1388a0ae4245a19bb6c02554c632633e356ddb989beb804fda96cfd47eba4fa460e7b277bc6b4ce4d07ed493"), 385}, "49cf14649f324a07e0d5bb2a00f7f05d5f5bdd6d14dff028e071327ec031104590eddb18f98b763e18bf382ff7c3875f30277f3179baebd795e7853fa643fdf280d8d7b81a2ab7829f615e132ab376d32194cd315908d27090e1180ce442d9be99322523db5bfac40ac5acb03550f5c93e5b01b1d71f2630868909a6a1250edb9abb2c6b0673e349f64c6577d4ba1b0a9c360016bae9478f8a80d5426327e84ea915c10ef39a016618b00aaae8735a8a1405180746ddd7ccd05dc890c5e5d07f49c40afdbc09267859ac5967b8c1163dc6defab955604e45e349a51df11d81b298424b84472607249a05b481ae88d98a9273ecdee009add0619641bd7d9f0b13a502e36e67b5836d0480a518a01046fa2738698fbe5e5008de11704b45531532667896158158ea08847a55a93f26fd6c99111b3017db1d1e6025d28d88ed3a419eb9c72e4fa3267f19c806092fd80cb91079cc00cefc55db53ad840ed1e6384f4cf02d9f2ecbaed54391e7a6da71fca4ea53ccfdd4d85adf37e4be8af1324f43ee"},
		{"sm3 case 15", args{[]byte("708993ef1388a0ae4245a19bb6c02554c632633e356ddb989beb804fda96cfd47eba4fa460e7b277bc6b4ce4d07ed493708993ef1388a0ae4245a19bb6c02554c632633e356ddb989beb804fda96cfd47eba4fa460e7b277bc6b4ce4d07ed493"), 416}, "49cf14649f324a07e0d5bb2a00f7f05d5f5bdd6d14dff028e071327ec031104590eddb18f98b763e18bf382ff7c3875f30277f3179baebd795e7853fa643fdf280d8d7b81a2ab7829f615e132ab376d32194cd315908d27090e1180ce442d9be99322523db5bfac40ac5acb03550f5c93e5b01b1d71f2630868909a6a1250edb9abb2c6b0673e349f64c6577d4ba1b0a9c360016bae9478f8a80d5426327e84ea915c10ef39a016618b00aaae8735a8a1405180746ddd7ccd05dc890c5e5d07f49c40afdbc09267859ac5967b8c1163dc6defab955604e45e349a51df11d81b298424b84472607249a05b481ae88d98a9273ecdee009add0619641bd7d9f0b13a502e36e67b5836d0480a518a01046fa2738698fbe5e5008de11704b45531532667896158158ea08847a55a93f26fd6c99111b3017db1d1e6025d28d88ed3a419eb9c72e4fa3267f19c806092fd80cb91079cc00cefc55db53ad840ed1e6384f4cf02d9f2ecbaed54391e7a6da71fca4ea53ccfdd4d85adf37e4be8af1324f43ee402f109ac6a77915fd7e248d3f14f3698dd0e8ea7ea27e4288b288d75b4343"},
		{"sm3 case 16", args{[]byte("708993ef1388a0ae4245a19bb6c02554c632633e356ddb989beb804fda96cfd47eba4fa460e7b277bc6b4ce4d07ed493708993ef1388a0ae4245a19bb6c02554c632633e356ddb989beb804fda96cfd47eba4fa460e7b277bc6b4ce4d07ed493"), 516}, "49cf14649f324a07e0d5bb2a00f7f05d5f5bdd6d14dff028e071327ec031104590eddb18f98b763e18bf382ff7c3875f30277f3179baebd795e7853fa643fdf280d8d7b81a2ab7829f615e132ab376d32194cd315908d27090e1180ce442d9be99322523db5bfac40ac5acb03550f5c93e5b01b1d71f2630868909a6a1250edb9abb2c6b0673e349f64c6577d4ba1b0a9c360016bae9478f8a80d5426327e84ea915c10ef39a016618b00aaae8735a8a1405180746ddd7ccd05dc890c5e5d07f49c40afdbc09267859ac5967b8c1163dc6defab955604e45e349a51df11d81b298424b84472607249a05b481ae88d98a9273ecdee009add0619641bd7d9f0b13a502e36e67b5836d0480a518a01046fa2738698fbe5e5008de11704b45531532667896158158ea08847a55a93f26fd6c99111b3017db1d1e6025d28d88ed3a419eb9c72e4fa3267f19c806092fd80cb91079cc00cefc55db53ad840ed1e6384f4cf02d9f2ecbaed54391e7a6da71fca4ea53ccfdd4d85adf37e4be8af1324f43ee402f109ac6a77915fd7e248d3f14f3698dd0e8ea7ea27e4288b288d75b4343ec8ab3d0cd9491a146e1b6033c512399bcd1cb9568d4f10d582f145c3ad7aae4ace7a14ec0abf831edc5aabcf58a1fb05180fa6e79651aa8753ddbf3ca0877b9a9d745ae1729b253f61cfc726cba4c9113008187830e41d428ca223014c994f317998689"},
	}
	for _, tt := range tests {
		wantBytes, _ := hex.DecodeString(tt.want)
		t.Run(tt.name, func(t *testing.T) {
			if got := Kdf(tt.args.z, tt.args.len); !reflect.DeepEqual(got, wantBytes) {
				t.Errorf("Kdf(%v,kLen=%v,zLen=%v) = %x, want %v", tt.name, tt.args.len, len(tt.args.z), got, tt.want)
			}
		})
	}
}

func TestKdfOldCase(t *testing.T) {
	x2, _ := new(big.Int).SetString("64D20D27D0632957F8028C1E024F6B02EDF23102A566C932AE8BD613A8E865FE", 16)
	y2, _ := new(big.Int).SetString("58D225ECA784AE300A81A2D48281A828E1CEDF11C4219099840265375077BF78", 16)

	expected := "006e30dae231b071dfad8aa379e90264491603"

	result := Kdf(append(x2.Bytes(), y2.Bytes()...), 19)

	resultStr := hex.EncodeToString(result)

	if expected != resultStr {
		t.Fatalf("expected %s, real value %s", expected, resultStr)
	}
}

func BenchmarkKdfWithSM3(b *testing.B) {
	tests := []struct {
		zLen int
		kLen int
	}{
		{32, 32},
		{32, 64},
		{32, 128},
		{64, 32},
		{64, 64},
		{64, 128},
		{64, 256},
		{64, 512},
		{64, 1024},
		{64, 1024 * 8},
	}
	z := make([]byte, 512)
	for _, tt := range tests {
		b.Run(fmt.Sprintf("zLen=%v-kLen=%v", tt.zLen, tt.kLen), func(b *testing.B) {
			b.SetBytes(int64(tt.kLen))
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				Kdf(z[:tt.zLen], tt.kLen)
			}
		})
	}
}

/*
func round1(a, b, c, d, e, f, g, h string, i int) {
	fmt.Printf("//Round %d\n", i+1)
	fmt.Printf("tt2 = bits.RotateLeft32(%s, 12)\n", a)
	fmt.Printf("ss1 = bits.RotateLeft32(tt2+%s+_K[%d], 7)\n", e, i)
	fmt.Printf("%s = %s ^ %s ^ %s + %s + (ss1 ^ tt2) + (w[%d] ^ w[%d])\n", d, a, b, c, d, i, i+4)
	fmt.Printf("tt2 = %s ^ %s ^ %s + %s + ss1 + w[%d]\n", e, f, g, h, i)
	fmt.Printf("%s = bits.RotateLeft32(%s, 9)\n", b, b)
	fmt.Printf("%s = bits.RotateLeft32(%s, 19)\n", f, f)
	fmt.Printf("%s = tt2 ^ bits.RotateLeft32(tt2, 9) ^ bits.RotateLeft32(tt2, 17)\n\n", h)
}

func round2(a, b, c, d, e, f, g, h string, i int) {
	fmt.Printf("//Round %d\n", i+1)
	fmt.Printf("w[%d] = p1(w[%d]^w[%d]^bits.RotateLeft32(w[%d], 15)) ^ bits.RotateLeft32(w[%d], 7) ^ w[%d]\n", i+4, i-12, i-5, i+1, i-9, i-2)
	fmt.Printf("tt2 = bits.RotateLeft32(%s, 12)\n", a)
	fmt.Printf("ss1 = bits.RotateLeft32(tt2+%s+_K[%d], 7)\n", e, i)
	fmt.Printf("%s = %s ^ %s ^ %s + %s + (ss1 ^ tt2) + (w[%d] ^ w[%d])\n", d, a, b, c, d, i, i+4)
	fmt.Printf("tt2 = %s ^ %s ^ %s + %s + ss1 + w[%d]\n", e, f, g, h, i)
	fmt.Printf("%s = bits.RotateLeft32(%s, 9)\n", b, b)
	fmt.Printf("%s = bits.RotateLeft32(%s, 19)\n", f, f)
	fmt.Printf("%s = tt2 ^ bits.RotateLeft32(tt2, 9) ^ bits.RotateLeft32(tt2, 17)\n\n", h)
}

func round3(a, b, c, d, e, f, g, h string, i int) {
	fmt.Printf("//Round %d\n", i+1)
	fmt.Printf("w[%d] = p1(w[%d]^w[%d]^bits.RotateLeft32(w[%d], 15)) ^ bits.RotateLeft32(w[%d], 7) ^ w[%d]\n", i+4, i-12, i-5, i+1, i-9, i-2)
	fmt.Printf("tt2 = bits.RotateLeft32(%s, 12)\n", a)
	fmt.Printf("ss1 = bits.RotateLeft32(tt2+%s+_K[%d], 7)\n", e, i)
	fmt.Printf("%s = %s&(%s|%s) | (%s & %s) + %s + (ss1 ^ tt2) + (w[%d] ^ w[%d])\n", d, a, b, c, b, c, d, i, i+4)
	fmt.Printf("tt2 = (%s^%s)&%s ^ %s + %s + ss1 + w[%d]\n", f, g, e, g, h, i)
	fmt.Printf("%s = bits.RotateLeft32(%s, 9)\n", b, b)
	fmt.Printf("%s = bits.RotateLeft32(%s, 19)\n", f, f)
	fmt.Printf("%s = tt2 ^ bits.RotateLeft32(tt2, 9) ^ bits.RotateLeft32(tt2, 17)\n\n", h)
}

func TestGenerateBlock(t *testing.T) {
	round1("a", "b", "c", "d", "e", "f", "g", "h", 0)
	round1("d", "a", "b", "c", "h", "e", "f", "g", 1)
	round1("c", "d", "a", "b", "g", "h", "e", "f", 2)
	round1("b", "c", "d", "a", "f", "g", "h", "e", 3)

	round1("a", "b", "c", "d", "e", "f", "g", "h", 4)
	round1("d", "a", "b", "c", "h", "e", "f", "g", 5)
	round1("c", "d", "a", "b", "g", "h", "e", "f", 6)
	round1("b", "c", "d", "a", "f", "g", "h", "e", 7)

	round1("a", "b", "c", "d", "e", "f", "g", "h", 8)
	round1("d", "a", "b", "c", "h", "e", "f", "g", 9)
	round1("c", "d", "a", "b", "g", "h", "e", "f", 10)
	round1("b", "c", "d", "a", "f", "g", "h", "e", 11)

	round2("a", "b", "c", "d", "e", "f", "g", "h", 12)
	round2("d", "a", "b", "c", "h", "e", "f", "g", 13)
	round2("c", "d", "a", "b", "g", "h", "e", "f", 14)
	round2("b", "c", "d", "a", "f", "g", "h", "e", 15)

	round3("a", "b", "c", "d", "e", "f", "g", "h", 16)
	round3("d", "a", "b", "c", "h", "e", "f", "g", 17)
	round3("c", "d", "a", "b", "g", "h", "e", "f", 18)
	round3("b", "c", "d", "a", "f", "g", "h", "e", 19)

	round3("a", "b", "c", "d", "e", "f", "g", "h", 20)
	round3("d", "a", "b", "c", "h", "e", "f", "g", 21)
	round3("c", "d", "a", "b", "g", "h", "e", "f", 22)
	round3("b", "c", "d", "a", "f", "g", "h", "e", 23)

	round3("a", "b", "c", "d", "e", "f", "g", "h", 24)
	round3("d", "a", "b", "c", "h", "e", "f", "g", 25)
	round3("c", "d", "a", "b", "g", "h", "e", "f", 26)
	round3("b", "c", "d", "a", "f", "g", "h", "e", 27)

	round3("a", "b", "c", "d", "e", "f", "g", "h", 28)
	round3("d", "a", "b", "c", "h", "e", "f", "g", 29)
	round3("c", "d", "a", "b", "g", "h", "e", "f", 30)
	round3("b", "c", "d", "a", "f", "g", "h", "e", 31)

	round3("a", "b", "c", "d", "e", "f", "g", "h", 32)
	round3("d", "a", "b", "c", "h", "e", "f", "g", 33)
	round3("c", "d", "a", "b", "g", "h", "e", "f", 34)
	round3("b", "c", "d", "a", "f", "g", "h", "e", 35)

	round3("a", "b", "c", "d", "e", "f", "g", "h", 36)
	round3("d", "a", "b", "c", "h", "e", "f", "g", 37)
	round3("c", "d", "a", "b", "g", "h", "e", "f", 38)
	round3("b", "c", "d", "a", "f", "g", "h", "e", 39)

	round3("a", "b", "c", "d", "e", "f", "g", "h", 40)
	round3("d", "a", "b", "c", "h", "e", "f", "g", 41)
	round3("c", "d", "a", "b", "g", "h", "e", "f", 42)
	round3("b", "c", "d", "a", "f", "g", "h", "e", 43)

	round3("a", "b", "c", "d", "e", "f", "g", "h", 44)
	round3("d", "a", "b", "c", "h", "e", "f", "g", 45)
	round3("c", "d", "a", "b", "g", "h", "e", "f", 46)
	round3("b", "c", "d", "a", "f", "g", "h", "e", 47)

	round3("a", "b", "c", "d", "e", "f", "g", "h", 48)
	round3("d", "a", "b", "c", "h", "e", "f", "g", 49)
	round3("c", "d", "a", "b", "g", "h", "e", "f", 50)
	round3("b", "c", "d", "a", "f", "g", "h", "e", 51)

	round3("a", "b", "c", "d", "e", "f", "g", "h", 52)
	round3("d", "a", "b", "c", "h", "e", "f", "g", 53)
	round3("c", "d", "a", "b", "g", "h", "e", "f", 54)
	round3("b", "c", "d", "a", "f", "g", "h", "e", 55)

	round3("a", "b", "c", "d", "e", "f", "g", "h", 56)
	round3("d", "a", "b", "c", "h", "e", "f", "g", 57)
	round3("c", "d", "a", "b", "g", "h", "e", "f", 58)
	round3("b", "c", "d", "a", "f", "g", "h", "e", 59)

	round3("a", "b", "c", "d", "e", "f", "g", "h", 60)
	round3("d", "a", "b", "c", "h", "e", "f", "g", 61)
	round3("c", "d", "a", "b", "g", "h", "e", "f", 62)
	round3("b", "c", "d", "a", "f", "g", "h", "e", 63)
}

func TestGenerateT(t *testing.T) {
	for i := 0; i < 16; i++ {
		fmt.Printf("0x%x, ", bits.RotateLeft32(_T0, i))
	}
	fmt.Println()
	for i := 16; i < 64; i++ {
		fmt.Printf("0x%x, ", bits.RotateLeft32(_T1, i))
	}
	fmt.Println()
}
*/
