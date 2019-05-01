package tezos_test

import (
	"fmt"
	"testing"

	"github.com/ecadlabs/signatory/tezos"
)

func TestValidate(t *testing.T) {
	type testCase struct {
		KeyPair     *tezos.KeyPair
		ExpectError bool
	}

	cases := []testCase{
		// Valid case
		testCase{
			KeyPair:     tezos.NewKeyPair("p2pk67PsiUBJZq9twKoFAWt8fSSVn53BR31dxKnTeLirLxHqB8gSnCq", "p2sk3LiJ6fU9Lvh8tdwar6tJ2Xg9bg3kQ9p4Sjmn83m29qJQdQPA5r"),
			ExpectError: false,
		},
		// Invalid secret key prefix
		testCase{
			KeyPair:     tezos.NewKeyPair("p2p67PsiUBJZq9twKoFAWt8fSSVn53BR31dxKnTeLirLxHqB8gSnCq", "p2sk3LiJ6fU9Lvh8tdwar6tJ2Xg9bg3kQ9p4Sjmn83m29qJQdQPA5r"),
			ExpectError: true,
		},
		// Invalid public key prefix
		testCase{
			KeyPair:     tezos.NewKeyPair("p2pk67PsiUBJZq9twKoFAWt8fSSVn53BR31dxKnTeLirLxHqB8gSnCq", "p2s3LiJ6fU9Lvh8tdwar6tJ2Xg9bg3kQ9p4Sjmn83m29qJQdQPA5r"),
			ExpectError: true,
		},
		// Invalid public key (checksum)
		testCase{
			KeyPair:     tezos.NewKeyPair("p2pk67PsiUBJZq9twKFAWt8fSSVn53BR31dxKnTeLirLxHqB8gSnCq", "p2sk3LiJ6fU9Lvh8tdwar6tJ2Xg9bg3kQ9p4Sjmn83m29qJQdQPA5r"),
			ExpectError: true,
		},
		// Invalid private key (checksum)
		testCase{
			KeyPair:     tezos.NewKeyPair("p2pk67PsiUBJZq9twKoFAWt8fSSVn53BR31dxKnTeLirLxHqB8gSnCq", "p2sk3Li6fU9Lvh8tdwar6tJ2Xg9bg3kQ9p4Sjmn83m29qJQdQPA5r"),
			ExpectError: true,
		},
		// Unsupported key
		testCase{
			KeyPair:     tezos.NewKeyPair("edpkvVPtveGg45XnB8a13kgXm9uLcPD3bqSCcaTdDfnpGUDw986oZy", "edsk4TjJWEszkHKono7XMnepVqwi37FrpbVt1KCsifJeAGimxheShG"),
			ExpectError: true,
		},
	}

	for _, testCase := range cases {
		keyPair := testCase.KeyPair
		err := keyPair.Validate()
		if !testCase.ExpectError && err != nil {
			fmt.Printf("Unexpected error was thrown: %s\n", err.Error())
			t.Fail()
		}

		if testCase.ExpectError && err == nil {
			fmt.Printf("Expected error but none was thrown\n")
			t.Fail()
		}
	}

}
