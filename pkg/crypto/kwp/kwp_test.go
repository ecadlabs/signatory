// Copyright 2020 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// Modifications copyright 2026 ECAD Labs Inc.

// Tests for AES Key Wrap with Padding (KWP).
//
// This file is derived from github.com/tink-crypto/tink
// (go/kwp/subtle/kwp_test.go). Tink-internal imports (random, testutil) have
// been replaced with crypto/rand. The Wycheproof JSON loader has been replaced
// with a selection of hardcoded Wycheproof known-answer test vectors
// (source: github.com/C2SP/wycheproof, testvectors_v1/aes_kwp_test.json).

package kwp

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"testing"
)

func randomBytes(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return b
}

func TestWrapUnwrap(t *testing.T) {
	kek := randomBytes(16)
	cipher, err := NewKWP(kek)
	if err != nil {
		t.Fatalf("failed to make kwp, error: %v", err)
	}

	for i := 16; i < 128; i++ {
		t.Run(fmt.Sprintf("MessageSize%d", i), func(t *testing.T) {
			toWrap := randomBytes(i)

			wrapped, err := cipher.Wrap(toWrap)
			if err != nil {
				t.Fatalf("failed to wrap, error: %v", err)
			}

			unwrapped, err := cipher.Unwrap(wrapped)
			if err != nil {
				t.Fatalf("failed to unwrap, error: %v", err)
			}

			if !bytes.Equal(toWrap, unwrapped) {
				t.Error("unwrapped doesn't match original key")
			}
		})
	}
}

func TestWrapUnwrap256(t *testing.T) {
	kek := randomBytes(32)
	cipher, err := NewKWP(kek)
	if err != nil {
		t.Fatalf("failed to make kwp with 256-bit key, error: %v", err)
	}

	for _, size := range []int{16, 24, 32, 64, 128, 256} {
		t.Run(fmt.Sprintf("MessageSize%d", size), func(t *testing.T) {
			toWrap := randomBytes(size)

			wrapped, err := cipher.Wrap(toWrap)
			if err != nil {
				t.Fatalf("failed to wrap, error: %v", err)
			}

			unwrapped, err := cipher.Unwrap(wrapped)
			if err != nil {
				t.Fatalf("failed to unwrap, error: %v", err)
			}

			if !bytes.Equal(toWrap, unwrapped) {
				t.Error("unwrapped doesn't match original key")
			}
		})
	}
}

func TestKeySizes(t *testing.T) {
	for i := 0; i < 255; i++ {
		expectSuccess := i == 16 || i == 32
		t.Run(fmt.Sprintf("KeySize%d", i), func(t *testing.T) {
			_, err := NewKWP(make([]byte, i))

			if expectSuccess && err != nil {
				t.Errorf("failed to create KWP: %v", err)
			}

			if !expectSuccess && err == nil {
				t.Error("created KWP with invalid key size")
			}
		})

	}
}

func TestInvalidWrappingSizes(t *testing.T) {
	kek := randomBytes(16)
	cipher, err := NewKWP(kek)
	if err != nil {
		t.Fatalf("failed to make kwp, error: %v", err)
	}

	for i := 0; i < 16; i++ {
		t.Run(fmt.Sprintf("KeySize%d", i), func(t *testing.T) {
			if _, err := cipher.Wrap(make([]byte, i)); err == nil {
				t.Error("wrapped a short key")
			}
		})
	}
}

func TestUnwrapModifiedCiphertext(t *testing.T) {
	kek := randomBytes(32)
	cipher, err := NewKWP(kek)
	if err != nil {
		t.Fatalf("failed to make kwp, error: %v", err)
	}

	original := randomBytes(32)
	wrapped, err := cipher.Wrap(original)
	if err != nil {
		t.Fatalf("failed to wrap, error: %v", err)
	}

	for i := range wrapped {
		modified := make([]byte, len(wrapped))
		copy(modified, wrapped)
		modified[i] ^= 0xFF

		if _, err := cipher.Unwrap(modified); err == nil {
			t.Errorf("unwrap succeeded on modified ciphertext at byte %d", i)
		}
	}
}

func TestWrappedSizeIsCorrect(t *testing.T) {
	kek := randomBytes(32)
	cipher, err := NewKWP(kek)
	if err != nil {
		t.Fatalf("NewKWP: %v", err)
	}

	for size := 16; size <= 256; size++ {
		wrapped, err := cipher.Wrap(randomBytes(size))
		if err != nil {
			t.Fatalf("Wrap(%d): %v", size, err)
		}
		expected := wrappingSize(size)
		if len(wrapped) != expected {
			t.Errorf("size %d: wrapped length %d, want %d", size, len(wrapped), expected)
		}
		if len(wrapped)%8 != 0 {
			t.Errorf("size %d: wrapped length %d is not a multiple of 8", size, len(wrapped))
		}
	}
}

func TestUnwrapTruncated(t *testing.T) {
	kek := randomBytes(16)
	cipher, err := NewKWP(kek)
	if err != nil {
		t.Fatalf("NewKWP: %v", err)
	}

	wrapped, err := cipher.Wrap(randomBytes(32))
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}

	// Truncating should always fail
	for i := 0; i < len(wrapped); i++ {
		if _, err := cipher.Unwrap(wrapped[:i]); err == nil {
			t.Errorf("unwrap succeeded on truncated ciphertext of length %d", i)
		}
	}
}

func TestDifferentKeyCannotUnwrap(t *testing.T) {
	cipher1, _ := NewKWP(randomBytes(32))
	cipher2, _ := NewKWP(randomBytes(32))

	wrapped, err := cipher1.Wrap(randomBytes(32))
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}

	if _, err := cipher2.Unwrap(wrapped); err == nil {
		t.Error("unwrap with different key should fail")
	}
}

// Wycheproof known-answer test vectors for AES-KWP.
// Source: github.com/C2SP/wycheproof testvectors_v1/aes_kwp_test.json
//
// These are deterministic vectors that pin the implementation to known-correct
// outputs, catching self-consistent-but-wrong implementations that roundtrip
// tests alone cannot detect.
func TestWycheproofVectors(t *testing.T) {
	mustHex := func(s string) []byte {
		b, err := hex.DecodeString(s)
		if err != nil {
			t.Fatalf("bad hex literal: %v", err)
		}
		return b
	}

	tests := []struct {
		name   string
		key    string
		msg    string
		ct     string
		result string // "valid" or "invalid"
	}{
		// 128-bit KEK, valid wrapping (tcId 1, 2, 3)
		{
			name:   "AES128_valid_tc1",
			key:    "6f67486d1e914419cb43c28509c7c1ea",
			msg:    "8dc0632d92ee0be4f740028410b08270",
			ct:     "8cd63fa6788aa5edfa753fc87d645a672b14107c3b4519e7",
			result: "valid",
		},
		{
			name:   "AES128_valid_tc2",
			key:    "a0b17172bb296db7f5c869e9a36b5ce3",
			msg:    "615dd022d607c910f20178cbdf42060f",
			ct:     "e8bac475d1429034b32f9bdeec09a37f9b3704028f1e0270",
			result: "valid",
		},
		{
			name:   "AES128_valid_tc3",
			key:    "0e49d571c19b5250effd41d94bde39d6",
			msg:    "f25e4de8caca363fd5f29442eb147b55",
			ct:     "4c8bcd601b508ef399f71b841294497a4493c4a0014c0103",
			result: "valid",
		},
		// 128-bit KEK, invalid (tcId 26, 27: 9-byte msg, below MinWrapSize
		// but tests unwrap of invalid ciphertext)
		{
			name:   "AES128_invalid_tc26",
			key:    "4f710eb6b5e28703becfc3dc52fa8bc1",
			msg:    "",
			ct:     "4cdd2962f23ec897d41d14c3f818516c055799185f459e2d",
			result: "invalid",
		},
		{
			name:   "AES128_invalid_tc27",
			key:    "4f710eb6b5e28703becfc3dc52fa8bc1",
			msg:    "",
			ct:     "de895192c35ec58ee6e5614fd2b20a85f8e9c8234cdc5319",
			result: "invalid",
		},
		// 256-bit KEK, valid wrapping (tcId 161, 162, 163)
		{
			name:   "AES256_valid_tc161",
			key:    "fce0429c610658ef8e7cfb0154c51de2239a8a317f5af5b6714f985fb5c4d75c",
			msg:    "287326b5ed0078e7ca0164d748f667e7",
			ct:     "e3eab96d9a2fda12f9e252053aff15e753e5ea6f5172c92b",
			result: "valid",
		},
		{
			name:   "AES256_valid_tc162",
			key:    "0dda6da5123e2c37c6fa16ba0d334cd01acd652f8994211751dfab4faac2fc22",
			msg:    "b40b6828729b456322a8d065abc0d081",
			ct:     "9d2b42fb2fdb92c89fb0c3bcd9e1600d3334b4e35e791369",
			result: "valid",
		},
		{
			name:   "AES256_valid_tc163",
			key:    "d6925914cd06308f81ad91e23073593d99d4e50351b20eb2a8d1a1ac4ced6588",
			msg:    "037b27b3dc95b19d15bd4091e320bfe1",
			ct:     "5291e05abd55f5886850855e3f9f2f576b101acc222d6766",
			result: "valid",
		},
		// 256-bit KEK, invalid (tcId 186, 187)
		{
			name:   "AES256_invalid_tc186",
			key:    "4f710eb6b5e28703becfc3dc52fa8bc1dd44a4a6d38a84b4f94e89ac32d987e7",
			msg:    "",
			ct:     "98428fb83dc207033c1585e0242e699be98e0001f1ee15ba",
			result: "invalid",
		},
		{
			name:   "AES256_invalid_tc187",
			key:    "4f710eb6b5e28703becfc3dc52fa8bc1dd44a4a6d38a84b4f94e89ac32d987e7",
			msg:    "",
			ct:     "60107f4c60c04c987c7c5810130303bd83fbc35d924f4482",
			result: "invalid",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			key := mustHex(tc.key)
			ct := mustHex(tc.ct)

			cipher, err := NewKWP(key)
			if err != nil {
				if tc.result == "valid" {
					t.Fatalf("NewKWP: %v", err)
				}
				return
			}

			switch tc.result {
			case "valid":
				msg := mustHex(tc.msg)

				wrapped, err := cipher.Wrap(msg)
				if err != nil {
					t.Fatalf("Wrap: %v", err)
				}
				if !bytes.Equal(wrapped, ct) {
					t.Errorf("Wrap mismatch\ngot:  %x\nwant: %x", wrapped, ct)
				}

				unwrapped, err := cipher.Unwrap(ct)
				if err != nil {
					t.Fatalf("Unwrap: %v", err)
				}
				if !bytes.Equal(unwrapped, msg) {
					t.Errorf("Unwrap mismatch\ngot:  %x\nwant: %x", unwrapped, msg)
				}

			case "invalid":
				if _, err := cipher.Unwrap(ct); err == nil {
					t.Error("Unwrap should have failed for invalid vector")
				}
			}
		})
	}
}
