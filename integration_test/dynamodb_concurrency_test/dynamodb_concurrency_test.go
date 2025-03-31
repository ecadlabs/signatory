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
	// Create two watermarks with the same level and round but different hashes
	// This simulates two different instances trying to sign the same block level
	hash1 := tz.BlockPayloadHash{1, 2, 3}
	hash2 := tz.BlockPayloadHash{4, 5, 6}

	wm1 := &request.Watermark{
		Level: 100,
		Round: 0,
		Hash:  tz.Some(hash1),
	}

	wm2 := &request.Watermark{
		Level: 100,
		Round: 0,
		Hash:  tz.Some(hash2),
	}

	// Test case 1: With the fix, this should now return false since levels and rounds are equal
	result := wm2.Validate(wm1)
	assert.False(t, result, "Watermark with same level/round should be rejected even with different hash")

	// Test case 2: Higher level should always be allowed
	wm3 := &request.Watermark{
		Level: 101,
		Round: 0,
		Hash:  tz.Some(hash2),
	}

	result = wm3.Validate(wm1)
	assert.True(t, result, "Watermark with higher level should be accepted")

	// Test case 3: Same level but higher round should be allowed
	wm4 := &request.Watermark{
		Level: 100,
		Round: 1,
		Hash:  tz.Some(hash2),
	}

	result = wm4.Validate(wm1)
	assert.True(t, result, "Watermark with same level but higher round should be accepted")
}
