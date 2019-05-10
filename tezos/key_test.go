package tezos_test

import (
	"fmt"
	"testing"

	"github.com/ecadlabs/signatory/tezos"
)

func TestValidate(t *testing.T) {
	type testCase struct {
		Name        string
		KeyPair     *tezos.KeyPair
		ExpectError bool
	}

	cases := []testCase{
		testCase{
			Name:        "Valid case",
			KeyPair:     tezos.NewKeyPair("p2pk67PsiUBJZq9twKoFAWt8fSSVn53BR31dxKnTeLirLxHqB8gSnCq", "p2sk3LiJ6fU9Lvh8tdwar6tJ2Xg9bg3kQ9p4Sjmn83m29qJQdQPA5r"),
			ExpectError: false,
		},
		testCase{
			Name:        "Invalid secret key prefix",
			KeyPair:     tezos.NewKeyPair("p2p67PsiUBJZq9twKoFAWt8fSSVn53BR31dxKnTeLirLxHqB8gSnCq", "p2sk3LiJ6fU9Lvh8tdwar6tJ2Xg9bg3kQ9p4Sjmn83m29qJQdQPA5r"),
			ExpectError: true,
		},
		testCase{
			Name:        "Invalid public key prefix",
			KeyPair:     tezos.NewKeyPair("p2pk67PsiUBJZq9twKoFAWt8fSSVn53BR31dxKnTeLirLxHqB8gSnCq", "p2s3LiJ6fU9Lvh8tdwar6tJ2Xg9bg3kQ9p4Sjmn83m29qJQdQPA5r"),
			ExpectError: true,
		},
		testCase{
			Name:        "Invalid public key (checksum)",
			KeyPair:     tezos.NewKeyPair("p2pk67PsiUBJZq9twKFAWt8fSSVn53BR31dxKnTeLirLxHqB8gSnCq", "p2sk3LiJ6fU9Lvh8tdwar6tJ2Xg9bg3kQ9p4Sjmn83m29qJQdQPA5r"),
			ExpectError: true,
		},
		testCase{
			Name:        "Invalid private key (checksum)",
			KeyPair:     tezos.NewKeyPair("p2pk67PsiUBJZq9twKoFAWt8fSSVn53BR31dxKnTeLirLxHqB8gSnCq", "p2sk3Li6fU9Lvh8tdwar6tJ2Xg9bg3kQ9p4Sjmn83m29qJQdQPA5r"),
			ExpectError: true,
		},
		testCase{
			Name:        "Unsupported key",
			KeyPair:     tezos.NewKeyPair("edpkvVPtveGg45XnB8a13kgXm9uLcPD3bqSCcaTdDfnpGUDw986oZy", "edsk4TjJWEszkHKono7XMnepVqwi37FrpbVt1KCsifJeAGimxheShG"),
			ExpectError: true,
		},
	}

	for _, testCase := range cases {
		t.Run(testCase.Name, func(t *testing.T) {
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
		})
	}

}
