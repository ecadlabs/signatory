package dynamodb_concurrency_test

// This test validates Signatory's watermark protection against double signing.
//
// To run this test:
// 1. Start a local DynamoDB instance:
//    docker run -p 8000:8000 amazon/dynamodb-local
// 2. Run the test:
//    go test -v .
//
// See README.md for more details.

import (
	"testing"

	tz "github.com/ecadlabs/gotez/v2"
	"github.com/ecadlabs/signatory/pkg/signatory/request"
	"github.com/stretchr/testify/assert"
)

// Tests the fix for the bug in Watermark.Validate logic that allowed double signing
func TestWatermarkValidateLogic(t *testing.T) {
	// Create two watermarks with the same level, round, AND hash
	// This simulates the actual bug scenario where two instances try to sign the same block
	hash1 := tz.BlockPayloadHash{1, 2, 3}

	wm1 := &request.Watermark{
		Level: 100,
		Round: 0,
		Hash:  tz.Some(hash1),
	}

	wm2 := &request.Watermark{
		Level: 100,
		Round: 0,
		Hash:  tz.Some(hash1), // SAME hash as wm1
	}

	// Test case 1: With the original buggy implementation, this would return true
	// because of the special hash comparison condition, allowing double signing
	// With the fix, this should return false since levels and rounds are equal
	result := wm2.Validate(wm1)

	// With the fix, this should return false (preventing double signing)
	// On the main branch without the fix, this will return true (allowing double signing)
	assert.False(t, result, "Watermark with same level/round/hash should be rejected to prevent double signing")

	// Test case 2: Different hash but same level/round - this would fail on both versions
	hash2 := tz.BlockPayloadHash{4, 5, 6}
	wm3 := &request.Watermark{
		Level: 100,
		Round: 0,
		Hash:  tz.Some(hash2), // Different hash, same level/round
	}

	result = wm3.Validate(wm1)
	assert.False(t, result, "Watermark with same level/round but different hash should still be rejected")

	// Test case 3: Higher level should always be allowed
	wm4 := &request.Watermark{
		Level: 101,
		Round: 0,
		Hash:  tz.Some(hash2),
	}

	result = wm4.Validate(wm1)
	assert.True(t, result, "Watermark with higher level should be accepted")

	// Test case 4: Same level but higher round should be allowed
	wm5 := &request.Watermark{
		Level: 100,
		Round: 1,
		Hash:  tz.Some(hash2),
	}

	result = wm5.Validate(wm1)
	assert.True(t, result, "Watermark with same level but higher round should be accepted")
}
