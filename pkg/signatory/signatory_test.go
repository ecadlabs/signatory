//go:build !integration

package signatory_test

import (
	"context"
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/ecadlabs/gotez/v2/crypt"
	"github.com/ecadlabs/signatory/pkg/config"
	"github.com/ecadlabs/signatory/pkg/hashmap"
	"github.com/ecadlabs/signatory/pkg/signatory"
	"github.com/ecadlabs/signatory/pkg/vault"
	"github.com/ecadlabs/signatory/pkg/vault/memory"
	"github.com/stretchr/testify/require"
	yaml "gopkg.in/yaml.v3"
)

const privateKey = "edsk4FTF78Qf1m2rykGpHqostAiq5gYW4YZEoGUSWBTJr2njsDHSnd"

func TestImport(t *testing.T) {
	conf := signatory.Config{
		Vaults:    map[string]*config.VaultConfig{"mock": {Driver: "mock"}},
		Watermark: signatory.IgnoreWatermark{},
		VaultFactory: vault.FactoryFunc(func(ctx context.Context, name string, conf *yaml.Node) (vault.Vault, error) {
			v, err := memory.New(nil, "Mock")
			if err != nil {
				return nil, err
			}
			return &memory.Importer{Vault: v}, nil
		}),
	}

	s, err := signatory.New(context.Background(), &conf)
	require.NoError(t, err)

	imported, err := s.Import(context.Background(), "mock", privateKey, nil, nil)
	require.NoError(t, err)
	require.Equal(t, "edpkv45regue1bWtuHnCgLU8xWKLwa9qRqv4gimgJKro4LSc3C5VjV", imported.PublicKey.String())
	require.Equal(t, "tz1LggX2HUdvJ1tF4Fvv8fjsrzLeW4Jr9t2Q", imported.PublicKeyHash.String())

	list, err := s.ListPublicKeys(context.Background())
	require.NoError(t, err)
	require.Equal(t, []*signatory.PublicKey{imported}, list)
}

func mustHex(s string) []byte {
	buf, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return buf
}

func TestPolicy(t *testing.T) {
	type testCase struct {
		title    string
		msg      []byte
		policy   signatory.PublicKeyPolicy
		expected string
	}

	var cases = []testCase{
		{
			title: "block ok",
			msg:   mustHex("11ed9d217c0000518e0118425847ac255b6d7c30ce8fec23b8eaf13b741de7d18509ac2ef83c741209630000000061947af504805682ea5d089837764b3efcc90b91db24294ff9ddb66019f332ccba17cc4741000000210000000102000000040000518e0000000000000004ffffffff0000000400000000eb1320a71e8bf8b0162a3ec315461e9153a38b70d00d5dde2df85eb92748f8d068d776e356683a9e23c186ccfb72ddc6c9857bb1704487972922e7c89a7121f800000000a8e1dd3c000000000000"),
			policy: signatory.PublicKeyPolicy{
				AllowedRequests: []string{"generic", "block", "endorsement"},
				AllowedOps:      []string{"endorsement", "seed_nonce_revelation", "activate_account", "ballot", "reveal", "transaction", "origination", "delegation"},
				LogPayloads:     true,
			},
		},
		{
			title: "block not allowed",
			msg:   mustHex("11ed9d217c0000518e0118425847ac255b6d7c30ce8fec23b8eaf13b741de7d18509ac2ef83c741209630000000061947af504805682ea5d089837764b3efcc90b91db24294ff9ddb66019f332ccba17cc4741000000210000000102000000040000518e0000000000000004ffffffff0000000400000000eb1320a71e8bf8b0162a3ec315461e9153a38b70d00d5dde2df85eb92748f8d068d776e356683a9e23c186ccfb72ddc6c9857bb1704487972922e7c89a7121f800000000a8e1dd3c000000000000"),
			policy: signatory.PublicKeyPolicy{
				AllowedRequests: []string{"generic", "endorsement"},
				AllowedOps:      []string{"endorsement", "seed_nonce_revelation", "activate_account", "ballot", "reveal", "transaction", "origination", "delegation"},
				LogPayloads:     true,
			},
			expected: "request kind `block' is not allowed",
		},
		{
			title: "endorsement ok",
			msg:   mustHex("13ed9d217cfc81eee810737b04018acef4db74d056b79edc43e6be46cae7e4c217c22a82f01500120000518d0000000003e7ea1f67dbb0bb6cfa372cb092cd9cf786b4f1b5e5139da95b915fb95e698d"),
			policy: signatory.PublicKeyPolicy{
				AllowedRequests: []string{"generic", "block", "endorsement"},
				AllowedOps:      []string{"endorsement", "seed_nonce_revelation", "activate_account", "ballot", "reveal", "transaction", "origination", "delegation"},
				LogPayloads:     true,
			},
		},
		// {
		// 	title: "endorsement not allowed",
		// 	msg:   mustHex("13ed9d217cfc81eee810737b04018acef4db74d056b79edc43e6be46cae7e4c217c22a82f01500120000518d0000000003e7ea1f67dbb0bb6cfa372cb092cd9cf786b4f1b5e5139da95b915fb95e698d"),
		// 	policy: signatory.PublicKeyPolicy{
		// 		AllowedRequests: []string{"generic", "block"},
		// 		AllowedOps:      []string{"seed_nonce_revelation", "activate_account", "ballot", "reveal", "transaction", "origination", "delegation", "update_consensus_key"},
		// 		LogPayloads:     true,
		// 	},
		// 	expected: "request kind `endorsement' is not allowed",
		// },
		{
			title: "generic ok",
			msg:   mustHex("03a60703a9567bf69ec66b368c3d8562eba4cbf29278c2c10447a684e3aa1436856c00a0c7a9b0bcd6a48ee0c13094327f215ba2adeaa7d40dabc1af25e36fde02c096b10201f525eabd8b0eeace1494233ea0230d2c9ad6619b00ffff0b66756c66696c6c5f61736b0000000907070088f0f6010306"),
			policy: signatory.PublicKeyPolicy{
				AllowedRequests: []string{"generic", "block", "endorsement"},
				AllowedOps:      []string{"endorsement", "seed_nonce_revelation", "activate_account", "ballot", "reveal", "transaction", "origination", "delegation"},
				LogPayloads:     true,
			},
		},
		{
			title: "generic not allowed",
			msg:   mustHex("03573a2d2d49a3b9634d1605c3aa48ebdd5d21a5885ad17aa44c2b1d0dbcbcac686c004b415314d2b56b0481a3ae8c992ce8bb8dba0369d086039ecb2dc35000c0843d000076b2f1ea1cf6753888ac5488693977446652d79e00"),
			policy: signatory.PublicKeyPolicy{
				AllowedRequests: []string{"block", "endorsement"},
				AllowedOps:      []string{"endorsement", "seed_nonce_revelation", "activate_account", "ballot", "reveal", "origination", "delegation"},
				LogPayloads:     true,
			},
			expected: "request kind `generic' is not allowed",
		},
		{
			title: "delegation ok",
			msg:   mustHex("03b89591b37be370e3db3fc7f77fdd176c5153f75ddcd239094c7ebeb66ee5e8bd6e002ea14368f6494539861ba04cf8cc946ace12cfd4ea09d89f40f44e00ff004b415314d2b56b0481a3ae8c992ce8bb8dba0369"),
			policy: signatory.PublicKeyPolicy{
				AllowedRequests: []string{"generic", "block", "endorsement"},
				AllowedOps:      []string{"endorsement", "seed_nonce_revelation", "activate_account", "ballot", "reveal", "transaction", "origination", "delegation"},
				LogPayloads:     true,
			},
		},
		{
			title: "delegation not allowed",
			msg:   mustHex("03b89591b37be370e3db3fc7f77fdd176c5153f75ddcd239094c7ebeb66ee5e8bd6e002ea14368f6494539861ba04cf8cc946ace12cfd4ea09d89f40f44e00ff004b415314d2b56b0481a3ae8c992ce8bb8dba0369"),
			policy: signatory.PublicKeyPolicy{
				AllowedRequests: []string{"generic", "block", "endorsement"},
				AllowedOps:      []string{"endorsement", "seed_nonce_revelation", "activate_account", "ballot", "reveal", "origination"},
				LogPayloads:     true,
			},
			expected: "operation `delegation' is not allowed",
		},
		{
			title: "origination ok",
			msg:   mustHex("03742d8e0a99049a5053bd71ac18b40fbb1f20e262e45dec88acd6795ba75147066d004b415314d2b56b0481a3ae8c992ce8bb8dba0369d80aa1cb2d8156bb0200000000001c02000000170500035b0501035b050202000000080316053d036d0342000000020000"),
			policy: signatory.PublicKeyPolicy{
				AllowedRequests: []string{"generic", "block", "endorsement"},
				AllowedOps:      []string{"endorsement", "seed_nonce_revelation", "activate_account", "ballot", "reveal", "transaction", "origination", "delegation"},
				LogPayloads:     true,
			},
		},
		{
			title: "origination not allowed",
			msg:   mustHex("03742d8e0a99049a5053bd71ac18b40fbb1f20e262e45dec88acd6795ba75147066d004b415314d2b56b0481a3ae8c992ce8bb8dba0369d80aa1cb2d8156bb0200000000001c02000000170500035b0501035b050202000000080316053d036d0342000000020000"),
			policy: signatory.PublicKeyPolicy{
				AllowedRequests: []string{"generic", "block", "endorsement"},
				AllowedOps:      []string{"endorsement", "seed_nonce_revelation", "activate_account", "ballot", "reveal", "transaction", "delegation"},
				LogPayloads:     true,
			},
			expected: "operation `origination' is not allowed",
		},
		{
			title: "reveal ok",
			msg:   mustHex("03573a2d2d49a3b9634d1605c3aa48ebdd5d21a5885ad17aa44c2b1d0dbcbcac686c004b415314d2b56b0481a3ae8c992ce8bb8dba0369d086039ecb2dc35000c0843d000076b2f1ea1cf6753888ac5488693977446652d79e00"),
			policy: signatory.PublicKeyPolicy{
				AllowedRequests: []string{"generic", "block", "endorsement"},
				AllowedOps:      []string{"endorsement", "seed_nonce_revelation", "activate_account", "ballot", "reveal", "transaction", "origination", "delegation"},
				LogPayloads:     true,
			},
		},
		{
			title: "reveal not allowed",
			msg:   mustHex("0333faca8a156c5e69fc8a63a799911b7c94b126fc7294dbbc0b8cb6880a81944e6b0008460955bf19f2d43ff015d938d53198b14ff637eb09f5ae3f904e000084d813c61c2478b2f30cda0b5593ae5ba293226f44120e42476f0e0941f3702a6e0008460955bf19f2d43ff015d938d53198b14ff6378a09f6ae3ff44e00ff004b415314d2b56b0481a3ae8c992ce8bb8dba0369"),
			policy: signatory.PublicKeyPolicy{
				AllowedRequests: []string{"generic", "block", "endorsement"},
				AllowedOps:      []string{"endorsement", "seed_nonce_revelation", "activate_account", "ballot", "transaction", "origination", "delegation"},
				LogPayloads:     true,
			},
			expected: "operation `reveal' is not allowed",
		},
		{
			title: "transaction ok",
			msg:   mustHex("03573a2d2d49a3b9634d1605c3aa48ebdd5d21a5885ad17aa44c2b1d0dbcbcac686c004b415314d2b56b0481a3ae8c992ce8bb8dba0369d086039ecb2dc35000c0843d000076b2f1ea1cf6753888ac5488693977446652d79e00"),
			policy: signatory.PublicKeyPolicy{
				AllowedRequests: []string{"generic", "block", "endorsement"},
				AllowedOps:      []string{"endorsement", "seed_nonce_revelation", "activate_account", "ballot", "reveal", "transaction", "origination", "delegation"},
				LogPayloads:     true,
			},
		},
		{
			title: "transaction not allowed",
			msg:   mustHex("03573a2d2d49a3b9634d1605c3aa48ebdd5d21a5885ad17aa44c2b1d0dbcbcac686c004b415314d2b56b0481a3ae8c992ce8bb8dba0369d086039ecb2dc35000c0843d000076b2f1ea1cf6753888ac5488693977446652d79e00"),
			policy: signatory.PublicKeyPolicy{
				AllowedRequests: []string{"generic", "block", "endorsement"},
				AllowedOps:      []string{"endorsement", "seed_nonce_revelation", "activate_account", "ballot", "reveal", "origination", "delegation"},
				LogPayloads:     true,
			},
			expected: "operation `transaction' is not allowed",
		},
		{
			title: "very long batch",
			msg:   mustHex("0355112cb64dad90a011aa59ff62346fbfd7d7cb850fe1851d1c46c5953e89a5776c00ad35d7a83666c904b295125a073c9d300f8dfee29b03de27f70b810280c2d72f0002c2db93219c85c47ee10f5806cd5e8600b024b4a1006c00ad35d7a83666c904b295125a073c9d300f8dfee29b03df27f70b810280c2d72f00024c5c29c5784ec0a617c59c9c3803f70be15ed55a006c00ad35d7a83666c904b295125a073c9d300f8dfee29b03e027f70b810280c2d72f000278e73409856a35087a53ba3fb7edfa36fcb7a205006c00ad35d7a83666c904b295125a073c9d300f8dfee29b03e127f70b810280c2d72f0002ddc837e0318586efdebab633ef0299718ece207d006c00ad35d7a83666c904b295125a073c9d300f8dfee29b03e227f70b810280c2d72f00027865dcc61de475963a28f395dbd6e03fe6243178006c00ad35d7a83666c904b295125a073c9d300f8dfee29b03e327f70b810280c2d72f000211079543c5e1591400a691f719e1655dc6eebd74006c00ad35d7a83666c904b295125a073c9d300f8dfee29b03e427f70b810280c2d72f00028cc3b237ace98a9fca1089c928ede20240da35b6006c00ad35d7a83666c904b295125a073c9d300f8dfee29b03e527f70b810280c2d72f00021016f12477e1617dcbaeedb1d361695b6dac94a3006c00ad35d7a83666c904b295125a073c9d300f8dfee29b03e627f70b810280c2d72f0002c62e00941cbb5076b0577b6db560b421a11fd63f006c00ad35d7a83666c904b295125a073c9d300f8dfee29b03e727f70b810280c2d72f000234c739e027dc020cc0b65b0b0dae820de88a63af006c00ad35d7a83666c904b295125a073c9d300f8dfee29b03e827f70b810280c2d72f00022a941d7990c4cf7e09fab0a0a75f1168e14c71e5006c00ad35d7a83666c904b295125a073c9d300f8dfee29b03e927f70b810280c2d72f00023c52609a7d9de252b792b9a8d5fdbcf5e858b5e7006c00ad35d7a83666c904b295125a073c9d300f8dfee29b03ea27f70b810280c2d72f0002d2f0b93661f9441b2d750a6c665fcefb6cb34027006c00ad35d7a83666c904b295125a073c9d300f8dfee29b03eb27f70b810280c2d72f0002878fa7baa899d8bc66f3ba4e98aa0c26974f69d3006c00ad35d7a83666c904b295125a073c9d300f8dfee29b03ec27f70b810280c2d72f000238cd9f49f756c7d832a37ce61ab9731c8cea7cca006c00ad35d7a83666c904b295125a073c9d300f8dfee29b03ed27f70b810280c2d72f00022346320f3b7d2336ee93d8eb62a2b8a03a62fc0b006c00ad35d7a83666c904b295125a073c9d300f8dfee29b03ee27f70b810280c2d72f0002d5a80137b1c179f75db556f9c9a8830d55a22d21006c00ad35d7a83666c904b295125a073c9d300f8dfee29b03ef27f70b810280c2d72f0002583fc0bd9303f1a6b33628019a6bae422672ae24006c00ad35d7a83666c904b295125a073c9d300f8dfee29b03f027f70b810280c2d72f000281d6c6ca0d41b1054203273fcf8e9110fd366ce4006c00ad35d7a83666c904b295125a073c9d300f8dfee29b03f127f70b810280c2d72f00021ae32864bf3d0605bf904468c66ebdd39545640c006c00ad35d7a83666c904b295125a073c9d300f8dfee29b03f227f70b810280c2d72f000212ec366510fe5444e1491d15d07e72abfcf51ac0006c00ad35d7a83666c904b295125a073c9d300f8dfee29b03f327f70b810280c2d72f000233220795a281da0b986b112197b641d61cb2ba03006c00ad35d7a83666c904b295125a073c9d300f8dfee29b03f427f70b810280c2d72f000250863846b10d301d540e3bd009a3bd0dcd8e59c9006c00ad35d7a83666c904b295125a073c9d300f8dfee29b03f527f70b810280c2d72f00026365518ac6d3bb24582f3f05308d9480c2d504a2006c00ad35d7a83666c904b295125a073c9d300f8dfee29b03f627f70b810280c2d72f00026bd9137a7c3cbb1b23b3ef454ea95eba6143e316006c00ad35d7a83666c904b295125a073c9d300f8dfee29b03f727f70b810280c2d72f00021f9ebbdecafa6675be9a27629f0e180ec6e00f61006c00ad35d7a83666c904b295125a073c9d300f8dfee29b03f827f70b810280c2d72f0002889b7e5fc9f3ea7dd8d2affa81bd4c82d1f90d24006c00ad35d7a83666c904b295125a073c9d300f8dfee29b03f927f70b810280c2d72f000227426f805df610ab76d44e437818d507f85b81c1006c00ad35d7a83666c904b295125a073c9d300f8dfee29b03fa27f70b810280c2d72f0002ec902fa148de8ab95df652c1382194b1f74545b2006c00ad35d7a83666c904b295125a073c9d300f8dfee29b03fb27f70b810280c2d72f0002ba07ac1c3e0c03edaa4b37931a8eddcc457df789006c00ad35d7a83666c904b295125a073c9d300f8dfee29b03fc27f70b810280c2d72f0002ff7e08b25dd76ef1a33234ca3e465214661ab961006c00ad35d7a83666c904b295125a073c9d300f8dfee29b03fd27f70b810280c2d72f00026f5df103b62b7dd4c21e7331a201d73feaea605d006c00ad35d7a83666c904b295125a073c9d300f8dfee29b03fe27f70b810280c2d72f0002210095c91d2bef29fcb5ba276bc1907bd9bc12cf006c00ad35d7a83666c904b295125a073c9d300f8dfee29b03ff27f70b810280c2d72f000215f1726af297a108398bd48f2432607498c260aa006c00ad35d7a83666c904b295125a073c9d300f8dfee29b038028f70b810280c2d72f00022f5bfb0de88b6d8a36046d988d23930e51eae842006c00ad35d7a83666c904b295125a073c9d300f8dfee29b038128f70b810280c2d72f000294ad3e8152556c69b3810ae86ebc43e8538bac13006c00ad35d7a83666c904b295125a073c9d300f8dfee29b038228f70b810280c2d72f00029bdb2df82d79db535d5053e9267f7693bb88b24b006c00ad35d7a83666c904b295125a073c9d300f8dfee29b038328f70b810280c2d72f0002b864e7b3d711ea286f1268183717291f3fc15b67006c00ad35d7a83666c904b295125a073c9d300f8dfee29b038428f70b810280c2d72f00025f3307112e0c1272b0f99be5201c236321a4a8dc006c00ad35d7a83666c904b295125a073c9d300f8dfee29b038528f70b810280c2d72f00025ae753fcca1483d92adaf5494093a60a38652b0c006c00ad35d7a83666c904b295125a073c9d300f8dfee29b038628f70b810280c2d72f000203e48809786876e06788f36c03b476cf84fe07f4006c00ad35d7a83666c904b295125a073c9d300f8dfee29b038728f70b810280c2d72f000217a36bc67f31733d782e520d7d56cf6bbab608b9006c00ad35d7a83666c904b295125a073c9d300f8dfee29b038828f70b810280c2d72f0002eb34a893f1304be7949228f61f45b9020113e3db006c00ad35d7a83666c904b295125a073c9d300f8dfee29b038928f70b810280c2d72f000283483b61bdc8043e9be5e138a1e071ba23310090006c00ad35d7a83666c904b295125a073c9d300f8dfee29b038a28f70b810280c2d72f0002b6b1875b1ef33f67ea657fb8816e3bea94a0585e006c00ad35d7a83666c904b295125a073c9d300f8dfee29b038b28f70b810280c2d72f00020dbf4b0150461787aa2ada57a6608cca1efb83d0006c00ad35d7a83666c904b295125a073c9d300f8dfee29b038c28f70b810280c2d72f0002d7bbc19ed1810513204cf2d5b550669c280633b1006c00ad35d7a83666c904b295125a073c9d300f8dfee29b038d28f70b810280c2d72f0002f7e06a7f04c17f4830f9335c73383e2033e1e412006c00ad35d7a83666c904b295125a073c9d300f8dfee29b038e28f70b810280c2d72f0002b3b50b942f13f0a4c39cbb3386c42be503fe120e006c00ad35d7a83666c904b295125a073c9d300f8dfee29b038f28f70b810280c2d72f0002749269f71e88be29fda28242cd7300e1eb3755ec006c00ad35d7a83666c904b295125a073c9d300f8dfee29b039028f70b810280c2d72f00029f347c7c39c77bd0ee35be7fe33ad364db96a28e006c00ad35d7a83666c904b295125a073c9d300f8dfee29b039128f70b810280c2d72f00026e54bbed73ad2f406e707caf85dc85b054d4bd64006c00ad35d7a83666c904b295125a073c9d300f8dfee29b039228f70b810280c2d72f0002cf6e67bf5bf6184b987928de10099daf47a7e26f006c00ad35d7a83666c904b295125a073c9d300f8dfee29b039328f70b810280c2d72f00027def95def8583355372d7b94dcc3730b99db7579006c00ad35d7a83666c904b295125a073c9d300f8dfee29b039428f70b810280c2d72f0002382582eaba432b6b4da73d3c8d9540fff6b0e611006c00ad35d7a83666c904b295125a073c9d300f8dfee29b039528f70b810280c2d72f0002992d189f46dd3586f4cea0abc31e3c28e7dbde7e006c00ad35d7a83666c904b295125a073c9d300f8dfee29b039628f70b810280c2d72f000249cf8e04ebc706ad52aa4b26218bf82abab9c65d006c00ad35d7a83666c904b295125a073c9d300f8dfee29b039728f70b810280c2d72f0002c61114f3bd9cddcec8e26da5a3e6688126c4afc1006c00ad35d7a83666c904b295125a073c9d300f8dfee29b039828f70b810280c2d72f0002d5c5eba0dc80207515008f82ac11d89e0dc28c74006c00ad35d7a83666c904b295125a073c9d300f8dfee29b039928f70b810280c2d72f0002a016654621b6c5038c70a25665c222e2de06b327006c00ad35d7a83666c904b295125a073c9d300f8dfee29b039a28f70b810280c2d72f000229b599e0e134ed433879f7d8e61d34767202ff10006c00ad35d7a83666c904b295125a073c9d300f8dfee29b039b28f70b810280c2d72f00026ff469be10bc6f00db89bf3a3967f7e796f6030d006c00ad35d7a83666c904b295125a073c9d300f8dfee29b039c28f70b810280c2d72f000217b499468732fad1eef2ca81b1e0f7e8b4b1350e006c00ad35d7a83666c904b295125a073c9d300f8dfee29b039d28f70b810280c2d72f00025a01ac5c3c6077877a925e2680d969fb0fb7ca53006c00ad35d7a83666c904b295125a073c9d300f8dfee29b039e28f70b810280c2d72f0002c11868db599d23c4c87be511196160b77dd47bef006c00ad35d7a83666c904b295125a073c9d300f8dfee29b039f28f70b810280c2d72f000226749fd65e3188b4e1328a8bad927e4e91f719e4006c00ad35d7a83666c904b295125a073c9d300f8dfee29b03a028f70b810280c2d72f0002e45e7ffffc6ed9760699efca66ffe320f37b14d8006c00ad35d7a83666c904b295125a073c9d300f8dfee29b03a128f70b810280c2d72f000269074be8e89c5da38d586b1b4d93f04ae31014d1006c00ad35d7a83666c904b295125a073c9d300f8dfee29b03a228f70b810280c2d72f00024da643f226b13ae2e5ca0a1a4f4dcfc08ee78205006c00ad35d7a83666c904b295125a073c9d300f8dfee29b03a328f70b810280c2d72f00022733018d2e63864dff513110bb84098aac9068ba006c00ad35d7a83666c904b295125a073c9d300f8dfee29b03a428f70b810280c2d72f0002e3dcff9a5548bbd0accef8bc1844c6e8c61037d5006c00ad35d7a83666c904b295125a073c9d300f8dfee29b03a528f70b810280c2d72f00021d81d2e184dded9dcf176a4dfaccb97f63b873e3006c00ad35d7a83666c904b295125a073c9d300f8dfee29b03a628f70b810280c2d72f000297567eb85042113aae65792cc4de66f34ea92dd2006c00ad35d7a83666c904b295125a073c9d300f8dfee29b03a728f70b810280c2d72f000223b32c2785a5d0f855f96157344a7ba266d2f06a006c00ad35d7a83666c904b295125a073c9d300f8dfee29b03a828f70b810280c2d72f000274ec2ebc5ae427f9b2f388f9435113a4298b0b7a006c00ad35d7a83666c904b295125a073c9d300f8dfee29b03a928f70b810280c2d72f0002ba145666c287aa5de2b16cccd719a0f96b2b8248006c00ad35d7a83666c904b295125a073c9d300f8dfee29b03aa28f70b810280c2d72f000218d1ebf3428ae43eb0b9fb96eccf20989881550e006c00ad35d7a83666c904b295125a073c9d300f8dfee29b03ab28f70b810280c2d72f000252ea3cfc9ac3ba30333cf5d8d4ac55449d428b1c006c00ad35d7a83666c904b295125a073c9d300f8dfee29b03ac28f70b810280c2d72f0002634020fad9580691d53d9434ced83192e8388fbc006c00ad35d7a83666c904b295125a073c9d300f8dfee29b03ad28f70b810280c2d72f0002d3f68869a42c65a70b5ddf40b2f33f19672d9e49006c00ad35d7a83666c904b295125a073c9d300f8dfee29b03ae28f70b810280c2d72f0002bc17a3827df6823722601eef76d73b1f7ffb0126006c00ad35d7a83666c904b295125a073c9d300f8dfee29b03af28f70b810280c2d72f0002db055290b1d62e5fc9d46c18aff15b9426d2af27006c00ad35d7a83666c904b295125a073c9d300f8dfee29b03b028f70b810280c2d72f00022e1a74d1ecea25ae98dcc1b59fbf1d562ee0d25a006c00ad35d7a83666c904b295125a073c9d300f8dfee29b03b128f70b810280c2d72f000226c62dc6eac189190c3bd3c8286c646f8a693314006c00ad35d7a83666c904b295125a073c9d300f8dfee29b03b228f70b810280c2d72f000205b59840171123d6400f00085cdcc84c2229ea19006c00ad35d7a83666c904b295125a073c9d300f8dfee29b03b328f70b810280c2d72f0002e4d81df4354f686b8112c6ade724762b63c534cc006c00ad35d7a83666c904b295125a073c9d300f8dfee29b03b428f70b810280c2d72f0002164fa4a4aeba4c706c6321fca63cbad821554674006c00ad35d7a83666c904b295125a073c9d300f8dfee29b03b528f70b810280c2d72f0002cfab1cae8f8b4a5a1625fb29834a4033b71e68f1006c00ad35d7a83666c904b295125a073c9d300f8dfee29b03b628f70b810280c2d72f0002358ed38ee34b48912ca129d831ef0a28cffa70c8006c00ad35d7a83666c904b295125a073c9d300f8dfee29b03b728f70b810280c2d72f00027af2b83f38382c77c0973fffcecda9786edcacfa006c00ad35d7a83666c904b295125a073c9d300f8dfee29b03b828f70b810280c2d72f0002d9bd3cf2c5aa2742795e03b62f82a941d399181d006c00ad35d7a83666c904b295125a073c9d300f8dfee29b03b928f70b810280c2d72f000256aff58a831cd47b8d97ae7d184924fca3c7f5da006c00ad35d7a83666c904b295125a073c9d300f8dfee29b03ba28f70b810280c2d72f0002896f25380669cbf096d36b9923a612cbe01fa62d006c00ad35d7a83666c904b295125a073c9d300f8dfee29b03bb28f70b810280c2d72f0002d4ff5886058c7ee0d33a023ff25d0f8b016698b5006c00ad35d7a83666c904b295125a073c9d300f8dfee29b03bc28f70b810280c2d72f000204945aebc6c53bdcc7e533ab55d9446d23f94a77006c00ad35d7a83666c904b295125a073c9d300f8dfee29b03bd28f70b810280c2d72f0002d73db8930e49ef80b322414d46deb889444f2b0b006c00ad35d7a83666c904b295125a073c9d300f8dfee29b03be28f70b810280c2d72f00028f2a2872ef501c6d50621e8365db8fe21209c35b006c00ad35d7a83666c904b295125a073c9d300f8dfee29b03bf28f70b810280c2d72f00029356c83ecdf71b74162a532b828a15cb0592e7a9006c00ad35d7a83666c904b295125a073c9d300f8dfee29b03c028f70b810280c2d72f0002621c4bd04937975fcb9be7c7dc7837763555efc0006c00ad35d7a83666c904b295125a073c9d300f8dfee29b03c128f70b810280c2d72f0002513d4f44da9ace3177a465ec99a7672ed84e9222006c00ad35d7a83666c904b295125a073c9d300f8dfee29b03c228f70b810280c2d72f000210128df46081bf846aa241474506e43219bc16d6006c00ad35d7a83666c904b295125a073c9d300f8dfee29b03c328f70b810280c2d72f00022c61e5527f6142c93781795a758418b1c9d04e37006c00ad35d7a83666c904b295125a073c9d300f8dfee29b03c428f70b810280c2d72f000244ebcaa6d517d539c01394decf6fb80604c6f270006c00ad35d7a83666c904b295125a073c9d300f8dfee29b03c528f70b810280c2d72f00024a0e4f7c40d212864c9a0d959f260a33effbdcf0006c00ad35d7a83666c904b295125a073c9d300f8dfee29b03c628f70b810280c2d72f0002effd1e73fbf5318df44b6fd459422a2f3b46da21006c00ad35d7a83666c904b295125a073c9d300f8dfee29b03c728f70b810280c2d72f00021fbac147c8f2f3886882ee0529e81becbded0a43006c00ad35d7a83666c904b295125a073c9d300f8dfee29b03c828f70b810280c2d72f0002b31dbdbac55ab7b8cb2f0882bc04c8d95a96781f006c00ad35d7a83666c904b295125a073c9d300f8dfee29b03c928f70b810280c2d72f0002712df23bdbe35c93079f1357bd1616ff20a26520006c00ad35d7a83666c904b295125a073c9d300f8dfee29b03ca28f70b810280c2d72f000277f11d6d2a5aba2859495651cbf08fcce5da6ddf006c00ad35d7a83666c904b295125a073c9d300f8dfee29b03cb28f70b810280c2d72f00023127eec59d340520b9932c2917b9227342124247006c00ad35d7a83666c904b295125a073c9d300f8dfee29b03cc28f70b810280c2d72f0002aa65c871cfb81d42697a6f5a2dec6fa66a448fad006c00ad35d7a83666c904b295125a073c9d300f8dfee29b03cd28f70b810280c2d72f00020ab17c61ad0306e0ba2e62d5c53b847350cb7061006c00ad35d7a83666c904b295125a073c9d300f8dfee29b03ce28f70b810280c2d72f0002f2191a88312c825e1e56d59b9fcc96e958695eb2006c00ad35d7a83666c904b295125a073c9d300f8dfee29b03cf28f70b810280c2d72f0002a04f0471c4e0ad02472da5633de149a05db681b9006c00ad35d7a83666c904b295125a073c9d300f8dfee29b03d028f70b810280c2d72f0002ea899399662c8a740ed096d83506287548a679b7006c00ad35d7a83666c904b295125a073c9d300f8dfee29b03d128f70b810280c2d72f0002d06658fea682ed5a15b28a94cf18fd0732fdef8f006c00ad35d7a83666c904b295125a073c9d300f8dfee29b03d228f70b810280c2d72f000207caa00a33d678448949d0a74552fcb74ee3be92006c00ad35d7a83666c904b295125a073c9d300f8dfee29b03d328f70b810280c2d72f00025480727df028dc64ec3e805e422526ab36ac4a0e006c00ad35d7a83666c904b295125a073c9d300f8dfee29b03d428f70b810280c2d72f0002bd164081c943d806a6c882fcf99abec70f98b792006c00ad35d7a83666c904b295125a073c9d300f8dfee29b03d528f70b810280c2d72f000223be6d051eb9bb5dad82fd917503c064c67bbbb7006c00ad35d7a83666c904b295125a073c9d300f8dfee29b03d628f70b810280c2d72f0002ee8cf10fb475d273344581a12b58cce1207e8b43006c00ad35d7a83666c904b295125a073c9d300f8dfee29b03d728f70b810280c2d72f0002c6113dbc0180d32fe5cc6cc1f398581dd74bdbda006c00ad35d7a83666c904b295125a073c9d300f8dfee29b03d828f70b810280c2d72f0002195141670ef5082d294fa8ded48556fd3ef83b9c006c00ad35d7a83666c904b295125a073c9d300f8dfee29b03d928f70b810280c2d72f000251e8e0f2e2ce2a66071df647d87f4d92a145590e006c00ad35d7a83666c904b295125a073c9d300f8dfee29b03da28f70b810280c2d72f00026cbfd6ab9b9db4f38b5c4713f55ca6e854dc4650006c00ad35d7a83666c904b295125a073c9d300f8dfee29b03db28f70b810280c2d72f000272f015911c80e45574ecac3df23a502e2497017b006c00ad35d7a83666c904b295125a073c9d300f8dfee29b03dc28f70b810280c2d72f0002cd9c495e2a39ec998ae0e44b7f43c6895cdc2cf3006c00ad35d7a83666c904b295125a073c9d300f8dfee29b03dd28f70b810280c2d72f0002772c71825a6da55d7638460d2150110c27c27615006c00ad35d7a83666c904b295125a073c9d300f8dfee29b03de28f70b810280c2d72f0002991cef00bdd4c666bacbf7b0b7d8493cfc8356d7006c00ad35d7a83666c904b295125a073c9d300f8dfee29b03df28f70b810280c2d72f0002189323bf20747d838ee81fd8aa147474e8b7ae75006c00ad35d7a83666c904b295125a073c9d300f8dfee29b03e028f70b810280c2d72f0002afd69e917efb531a38e1124d0bd273f5143b6fba006c00ad35d7a83666c904b295125a073c9d300f8dfee29b03e128f70b810280c2d72f000281d4110a42cd99c43aaffcd5ddb2494afca32c76006c00ad35d7a83666c904b295125a073c9d300f8dfee29b03e228f70b810280c2d72f0002e5987fd65df2a4892749751989cfd9abb6283b23006c00ad35d7a83666c904b295125a073c9d300f8dfee29b03e328f70b810280c2d72f000297c0f1bedd607f94c504df92652fb532f9aca326006c00ad35d7a83666c904b295125a073c9d300f8dfee29b03e428f70b810280c2d72f000203e9ba5d2f2f7b9559df03c4838b4257888af68f006c00ad35d7a83666c904b295125a073c9d300f8dfee29b03e528f70b810280c2d72f0002444c029b06b4a3cb13bc1d4bf6497a9d446c3516006c00ad35d7a83666c904b295125a073c9d300f8dfee29b03e628f70b810280c2d72f00026e37f12eabe563833f10d2a37e2d10814483ecec006c00ad35d7a83666c904b295125a073c9d300f8dfee29b03e728f70b810280c2d72f0002fd4f1f5ec18585d50bba7739174b7aebfbed618e006c00ad35d7a83666c904b295125a073c9d300f8dfee29b03e828f70b810280c2d72f0002929af098612427b1eff27fe7baf89d6cab7fc544006c00ad35d7a83666c904b295125a073c9d300f8dfee29b03e928f70b810280c2d72f00025159b985f0ec4aaec75a83281d0e752f4ab26680006c00ad35d7a83666c904b295125a073c9d300f8dfee29b03ea28f70b810280c2d72f0002d1e20a3ad6b13b6cd5e487a09859cb992895494d006c00ad35d7a83666c904b295125a073c9d300f8dfee29b03eb28f70b810280c2d72f00025cb23ddc6d18a63766ceb855aab4398a7274335f006c00ad35d7a83666c904b295125a073c9d300f8dfee29b03ec28f70b810280c2d72f0002a37defdea7dcb4b5002f6783841aacc87d0003b2006c00ad35d7a83666c904b295125a073c9d300f8dfee29b03ed28f70b810280c2d72f0002dd851a944c320b12f33c29cd2cfa0661f45ad7b0006c00ad35d7a83666c904b295125a073c9d300f8dfee29b03ee28f70b810280c2d72f000297ba93dbd9451c3fdd3043e0bead6433becc3bbc006c00ad35d7a83666c904b295125a073c9d300f8dfee29b03ef28f70b810280c2d72f00027fe64ded18fdc41af12dffd3fa95cded83813ef4006c00ad35d7a83666c904b295125a073c9d300f8dfee29b03f028f70b810280c2d72f0002aaa280bd62a12a9cd00cac30dc9f6b11aff7f4a6006c00ad35d7a83666c904b295125a073c9d300f8dfee29b03f128f70b810280c2d72f0002f3d038fb33c5f2f5e6f56c0a7766f1b5a45c1c13006c00ad35d7a83666c904b295125a073c9d300f8dfee29b03f228f70b810280c2d72f000237d4dc08dfb701da5e90c36df928ccc2507da329006c00ad35d7a83666c904b295125a073c9d300f8dfee29b03f328f70b810280c2d72f0002b42df74e0c96771b3d65713d97125a240a704cb500"),
			policy: signatory.PublicKeyPolicy{
				AllowedRequests: []string{"generic"},
				AllowedOps:      []string{"transaction"},
				LogPayloads:     true,
			},
		},
		{
			title: "increase paid storage ok",
			msg:   mustHex("031ca15e385360cc8843937ece7471307086020e8eaff1613c8c25124519710fe9710079cae4c9a1885f17d3995619bf28636c4394458bdd02ef8a09e807000101c83a61cd1cb193d2d7d5e49d867cc2299211575d00"),
			policy: signatory.PublicKeyPolicy{
				AllowedRequests: []string{"generic", "block", "endorsement"},
				AllowedOps:      []string{"endorsement", "seed_nonce_revelation", "activate_account", "ballot", "reveal", "origination", "delegation", "increase_paid_storage"},
				LogPayloads:     true,
			},
		},
		{
			title: "increase paid storage not allowed",
			msg:   mustHex("031ca15e385360cc8843937ece7471307086020e8eaff1613c8c25124519710fe9710079cae4c9a1885f17d3995619bf28636c4394458bdd02ef8a09e807000101c83a61cd1cb193d2d7d5e49d867cc2299211575d00"),
			policy: signatory.PublicKeyPolicy{
				AllowedRequests: []string{"generic", "block", "endorsement"},
				AllowedOps:      []string{"endorsement", "seed_nonce_revelation", "activate_account", "ballot", "reveal", "origination", "delegation"},
				LogPayloads:     true,
			},
			expected: "operation `increase_paid_storage' is not allowed",
		},
		{
			title: "VDF Revelation ok",
			msg:   mustHex("031ca15e385360cc8843937ece7471307086020e8eaff1613c8c25124519710fe9080079cae4c9a1885f17d3995619bf28636c4394458bdd02ef8a09e807000101c83a61cd1cb193d2d7d5e49d867cc2299211575d00031ca15e385360cc8843937ece7471307086020e8eaff1613c8c25124519710fe9080079cae4c9a1885f17d3995619bf28636c4394458bdd02ef8a09e807000101c83a61cd1cb193d2d7d5e49d867cc2299211575d00031ca15e385360cc8843937ece7471307086020e8eaff1613c8c25124519710fe9080079cae4c9a1885f17d3995619bf28636c4394458bdd02ef8a09e807"),
			policy: signatory.PublicKeyPolicy{
				AllowedRequests: []string{"generic", "block", "endorsement"},
				AllowedOps:      []string{"endorsement", "seed_nonce_revelation", "activate_account", "ballot", "reveal", "origination", "delegation", "vdf_revelation"},
				LogPayloads:     true,
			},
		},
		{
			title: "VDF Revelation not allowed",
			msg:   mustHex("031ca15e385360cc8843937ece7471307086020e8eaff1613c8c25124519710fe9080079cae4c9a1885f17d3995619bf28636c4394458bdd02ef8a09e807000101c83a61cd1cb193d2d7d5e49d867cc2299211575d00031ca15e385360cc8843937ece7471307086020e8eaff1613c8c25124519710fe9080079cae4c9a1885f17d3995619bf28636c4394458bdd02ef8a09e807000101c83a61cd1cb193d2d7d5e49d867cc2299211575d00031ca15e385360cc8843937ece7471307086020e8eaff1613c8c25124519710fe9080079cae4c9a1885f17d3995619bf28636c4394458bdd02ef8a09e807"),
			policy: signatory.PublicKeyPolicy{
				AllowedRequests: []string{"generic", "block", "endorsement"},
				AllowedOps:      []string{"endorsement", "seed_nonce_revelation", "activate_account", "ballot", "reveal", "origination", "delegation"},
				LogPayloads:     true,
			},
			expected: "operation `vdf_revelation' is not allowed",
		},
		{
			title: "Update consensus key",
			msg:   mustHex("03ebcaec6ed8ab1a8a515164df37f47be175fb92851249f2b83fb96b7434ec57d3720079cae4c9a1885f17d3995619bf28636c4394458bf102f31fcc08000202d56e7b5258aa58eeb61701476c46863e2f9f31b4b467ca3175fb2f1fed6b4106"),
			policy: signatory.PublicKeyPolicy{
				AllowedRequests: []string{"generic", "block", "endorsement"},
				AllowedOps:      []string{"endorsement", "seed_nonce_revelation", "activate_account", "ballot", "reveal", "origination", "delegation", "update_consensus_key"},
				LogPayloads:     true,
			},
		},
		{
			title: "Update consensus key not allowed",
			msg:   mustHex("03ebcaec6ed8ab1a8a515164df37f47be175fb92851249f2b83fb96b7434ec57d3720079cae4c9a1885f17d3995619bf28636c4394458bf102f31fcc08000202d56e7b5258aa58eeb61701476c46863e2f9f31b4b467ca3175fb2f1fed6b4106"),
			policy: signatory.PublicKeyPolicy{
				AllowedRequests: []string{"generic", "block", "endorsement"},
				AllowedOps:      []string{"endorsement", "seed_nonce_revelation", "activate_account", "ballot", "reveal", "origination", "delegation"},
				LogPayloads:     true,
			},
			expected: "operation `update_consensus_key' is not allowed",
		},
		{
			title: "Drain delegate",
			msg:   mustHex("0375959f80af0577302c9ed036371bc6c18644eeabf441fbad257c1a67d36a57fe090244cd5d0b4cb5a18d926b25bc37e58105e6786f0802f846b9ed8834c257a6f0c3cebeab4f58508b20ad0244cd5d0b4cb5a18d926b25bc37e58105e6786f08"),
			policy: signatory.PublicKeyPolicy{
				AllowedRequests: []string{"generic", "block", "endorsement"},
				AllowedOps:      []string{"endorsement", "seed_nonce_revelation", "activate_account", "ballot", "reveal", "origination", "delegation", "drain_delegate"},
				LogPayloads:     true,
			},
		},
		{
			title: "Drain delegate not allowed",
			msg:   mustHex("0375959f80af0577302c9ed036371bc6c18644eeabf441fbad257c1a67d36a57fe090244cd5d0b4cb5a18d926b25bc37e58105e6786f0802f846b9ed8834c257a6f0c3cebeab4f58508b20ad0244cd5d0b4cb5a18d926b25bc37e58105e6786f08"),
			policy: signatory.PublicKeyPolicy{
				AllowedRequests: []string{"generic", "block", "endorsement"},
				AllowedOps:      []string{"endorsement", "seed_nonce_revelation", "activate_account", "ballot", "reveal", "origination", "delegation", "update_consensus_key"},
				LogPayloads:     true,
			},
			expected: "operation `drain_delegate' is not allowed",
		},
		{
			title: "Delegate with consesus key",
			msg:   mustHex("03f6622bc2e0b99604f1f103f1cbda4fa1b07ad8a993838c4f62855bfe36e8fb6a6b02f846b9ed8834c257a6f0c3cebeab4f58508b20ade60215e807000202dbc1715493e74def32a7d219df06accd6ca75d775d4177dd09471f9a9a2302826e02f846b9ed8834c257a6f0c3cebeab4f58508b20adfa0116e80700ff02f846b9ed8834c257a6f0c3cebeab4f58508b20ad7202f846b9ed8834c257a6f0c3cebeab4f58508b20ad900217cc08000202ce4ab1f214186fc04b06383e012357ccf7b67f9bddbd5818dba80f704b3a79f4"),
			policy: signatory.PublicKeyPolicy{
				AllowedRequests: []string{"generic", "block", "endorsement"},
				AllowedOps:      []string{"endorsement", "seed_nonce_revelation", "activate_account", "ballot", "reveal", "origination", "delegation", "update_consensus_key"},
				LogPayloads:     true,
			},
		},
		{
			title: "Delegate with consesus key not allowed",
			msg:   mustHex("03f6622bc2e0b99604f1f103f1cbda4fa1b07ad8a993838c4f62855bfe36e8fb6a6b02f846b9ed8834c257a6f0c3cebeab4f58508b20ade60215e807000202dbc1715493e74def32a7d219df06accd6ca75d775d4177dd09471f9a9a2302826e02f846b9ed8834c257a6f0c3cebeab4f58508b20adfa0116e80700ff02f846b9ed8834c257a6f0c3cebeab4f58508b20ad7202f846b9ed8834c257a6f0c3cebeab4f58508b20ad900217cc08000202ce4ab1f214186fc04b06383e012357ccf7b67f9bddbd5818dba80f704b3a79f4"),
			policy: signatory.PublicKeyPolicy{
				AllowedRequests: []string{"generic", "block", "endorsement"},
				AllowedOps:      []string{"endorsement", "seed_nonce_revelation", "activate_account", "ballot", "reveal", "origination", "delegation"},
				LogPayloads:     true,
			},
			expected: "operation `update_consensus_key' is not allowed",
		},
	}

	priv, err := crypt.ParsePrivateKey([]byte(privateKey))
	require.NoError(t, err)
	pk := priv.Public()

	for _, c := range cases {
		t.Run(c.title, func(t *testing.T) {
			conf := signatory.Config{
				Vaults:    map[string]*config.VaultConfig{"mock": {Driver: "mock"}},
				Watermark: signatory.IgnoreWatermark{},
				VaultFactory: vault.FactoryFunc(func(ctx context.Context, name string, conf *yaml.Node) (vault.Vault, error) {
					return memory.NewUnparsed([]*memory.UnparsedKey{{Data: privateKey}}, "Mock"), nil
				}),
				Policy: hashmap.NewPublicKeyHashMap([]hashmap.PublicKeyKV[*signatory.PublicKeyPolicy]{{Key: pk.Hash(), Val: &c.policy}}),
			}

			s, err := signatory.New(context.Background(), &conf)
			require.NoError(t, err)
			require.NoError(t, s.Unlock(context.Background()))

			_, err = s.Sign(context.Background(), &signatory.SignRequest{PublicKeyHash: pk.Hash(), Message: c.msg})
			if c.expected != "" {
				require.EqualError(t, err, c.expected)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestListPublicKeys(t *testing.T) {
	type testCase struct {
		title    string
		policy   signatory.PublicKeyPolicy
		expected string
		lpk      ListPublicKeys
	}
	var cases = []testCase{
		{
			title: "ListPublicKeys with vault error",
			policy: signatory.PublicKeyPolicy{
				AllowedRequests: []string{"generic", "block", "endorsement"},
				AllowedOps:      []string{"endorsement", "seed_nonce_revelation", "activate_account", "ballot", "reveal", "transaction", "origination", "delegation"},
				LogPayloads:     true,
			},
			expected: "Vault not reachable",
			lpk: func(ctx context.Context) vault.StoredKeysIterator {
				return &TestKeyIterator{
					nxt: func(idx int) (key vault.StoredKey, err error) {
						return nil, fmt.Errorf("Vault not reachable")
					},
				}
			},
		},
		{
			title: "ListPublicKeys with done",
			policy: signatory.PublicKeyPolicy{
				AllowedRequests: []string{"generic", "block", "endorsement"},
				AllowedOps:      []string{"endorsement", "seed_nonce_revelation", "activate_account", "ballot", "reveal", "transaction", "origination", "delegation"},
				LogPayloads:     true,
			},
			lpk: func(ctx context.Context) vault.StoredKeysIterator {
				return &TestKeyIterator{
					nxt: func(idx int) (key vault.StoredKey, err error) {
						return nil, vault.ErrDone
					},
				}
			},
		},
		{
			title: "ListPublicKeys with key error",
			policy: signatory.PublicKeyPolicy{
				AllowedRequests: []string{"generic", "block", "endorsement"},
				AllowedOps:      []string{"endorsement", "seed_nonce_revelation", "activate_account", "ballot", "reveal", "transaction", "origination", "delegation"},
				LogPayloads:     true,
			},
			lpk: func(ctx context.Context) vault.StoredKeysIterator {
				return &TestKeyIterator{
					idx: 0,
					nxt: func(idx int) (key vault.StoredKey, err error) {
						if idx == 0 {
							return nil, vault.ErrKey
						} else {
							return nil, vault.ErrDone
						}
					},
				}
			},
		},
	}

	priv, err := crypt.ParsePrivateKey([]byte(privateKey))
	require.NoError(t, err)
	pk := priv.Public()

	for _, c := range cases {
		t.Run(c.title, func(t *testing.T) {
			conf := signatory.Config{
				Vaults:    map[string]*config.VaultConfig{"test": {Driver: "test"}},
				Watermark: signatory.IgnoreWatermark{},
				VaultFactory: vault.FactoryFunc(func(ctx context.Context, name string, conf *yaml.Node) (vault.Vault, error) {
					return NewTestVault(nil, c.lpk, nil, nil, "test"), nil
				}),
				Policy: hashmap.NewPublicKeyHashMap([]hashmap.PublicKeyKV[*signatory.PublicKeyPolicy]{{Key: pk.Hash(), Val: &c.policy}}),
			}
			s, err := signatory.New(context.Background(), &conf)
			require.NoError(t, err)
			require.NoError(t, s.Unlock(context.Background()))

			_, err = s.ListPublicKeys(context.Background())
			if c.expected != "" {
				require.EqualError(t, err, c.expected)
			} else {
				require.NoError(t, err)
			}
		})
	}
}
