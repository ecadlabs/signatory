package tests

// Keys defines all the public key hashes and other keys used in integration tests
// This file serves as a centralized reference for all keys used across test files

// Account aliases and their corresponding public key hashes
const (
	// Main test accounts
	AlicePKH    = "tz1VSUr8wwNhLAzempoch5d6hLRiTh8Cjcjb"
	BobPKH      = "tz1aSkwEot3L2kmUvcoxzjMomb9mvBNuzFK6"
	OpstestPKH  = "tz1RKGhRF4TZNCXEfwyqZshGsVfrZeVU446B"
	Opstest1PKH = "tz1R8HJMzVdZ9RqLCknxeq9w5rSbiqJ41szi"

	// Baker account for watermark tests
	BakerPKH = "tz1WGcYos3hL7GXYXjKrMnSFdkT7FyXnFBvf"
	// Baker account for operation kinds tests
	Baker1PKH = "tz1KqTpEZ7Yob7QbPE4Hy4Wo8fHG8LhKxZSx"

	// Authorized keys test account
	AuthTestPKH = "tz1QgHGuotVTCmYtA2Mr83FdiWLbwKqUvdnp"

	// Address type test accounts
	Tz1AliasPKH = "tz1dSrM2D7XcWPhdZpDxzNkmVLvdWSxApXaR"
	Tz2AliasPKH = "tz2QPsZoZse4eeahhg5DdfnBDB4VbU1PwgxN"
	Tz3AliasPKH = "tz3ZbCsUveF3Q6WUNkThT1wyJyhPunanaAXK"
	Tz4AliasPKH = "tz4XXtsYav3fZz2FSDa7hcx4F8sh8SaDWNME"

	Tz4PopPKH = "tz4Eb1d5L4njHViVgDDkas7qNgoZgDw6VYPz"
)

// Public keys corresponding to the public key hashes
const (
	// Main test accounts public keys
	AlicePK    = "edpkvGfYw3LyB1UcCahKQk4rF2tvbMUk8GFiTuMjL75uGXrpvKXhjn"
	BobPK      = "edpkurPsQ8eUApnLUJ9ZPDvu98E8VNj4KtJa1aZr16Cr5ow5VHKnz4"
	OpstestPK  = "edpkvSkEEfVMKvAv87env4kMNwLfuLYe7y7wXqgfvrwJwhJJpmL1GB"
	Opstest1PK = "edpktfLxRbpLeFjL49Rz2xtBwPaSfdZ7ZL6W3idm2JaMTP93RwmCdo"

	// Address type test accounts public keys
	Tz1AliasPK = "edpkvGfYw3LyB1UcCahKQk4rF2tvbMUk8GFiTuMjL75uGXrpvKXhjn"
	Tz2AliasPK = "sppk7cvVVMRRtYTdriTB6KQqpXZt9TUwSTcpMWq4FwpvG2eVZ56UuHP"
	Tz3AliasPK = "p2pk65pxFqFj1N66zRRQtdbEJWHMH5hRv4WsRkaGWQJtZ5bv8nVx6Dg"
	Tz4AliasPK = "BLpk1nRV5SBB2QCxsiem5Neoywcizr3mkdp167HL1iKFgFvzPhKo4RSy7J8JBh2BgGgVYjNsRGwU"

	Tz4PopPK = "BLpk1w7hcraa8qBo8f7sNBteUVoSejrS779YUra1deGqZgWSw8xUVYrNSMkxWrDAAwTtFtJxvMbK"
)

// Secret keys (for reference - these are used in signatory-local-secret.json)
const (
	// Main test accounts secret keys
	AliceSK    = "unencrypted:edsk3QoqBuvdamxouPhin7swCvkQNgq4jP5KZPbwWNnwdZpSpJiEbq"
	BobSK      = "unencrypted:edsk3RFfvaFaxbHx8BMtEW1rKQcPtDML3LXjNqMNLCzC3wLC1bWbAt"
	OpstestSK  = "unencrypted:edsk4ZuzTnZUqetnF7icqpjQ3RT9GPJQ8HAHTRHZhKQQjWmeneQJ7C"
	Opstest1SK = "unencrypted:edsk4DqHX7tUwsKPesv4iJyNJRaLu7ezZMDs8N5pwfeAbqtvEzLqx7"
	BakerSK    = "unencrypted:edsk3REH79xaoCkNizrDo8cY4WYwEkrFLTAdjb1pjcP9yQora4qE3Y"

	// Address type test accounts secret keys
	Tz1AliasSK = "unencrypted:edsk4BL896eCJ9t7ZPCdvSq1PKJB9MfqDRNYhYBLFQirmn7SWerPU3"
	Tz2AliasSK = "unencrypted:spsk1XYsTqUsd7LaLs9a8qpmCvLVJeLEZEXkeAZS5dwcKgUZhv3cYw"
	Tz3AliasSK = "unencrypted:p2sk2rUMnnnFPQCB7DBozkCZrFhiZ87ddrpAHbRcww7dwU2WHYUbci"
	Tz4AliasSK = "unencrypted:BLsk1XMDG3iepYGj15mBWc7dYjrkpVVM4VH3y5DyBCN9iAGrELwRbY"

	Tz4PopSK = "unencrypted:BLsk1d6zjtYgWxyZwdnCsQpwYcs3cJRFTMwJ1CWCgjFu4zpaZp9nL6"
)

// Authorized keys for authentication tests
const (
	// Authorized key used in authorizedkeys_test.go
	AuthKeyPK = "edpkujLb5ZCZ2gprnRzE9aVHKZfx9A8EtWu2xxkwYSjBUJbesJ9rWE"
	AuthKeySK = "unencrypted:edsk3ZAm9nqEo7qNugo2wcmxWnbDe7oUUmHt5UJYDdqwucsaHTAsVQ"
)

// Signatory service URLs for each account
const (
	// Main test accounts signatory URLs
	AliceSignatoryURL    = "http://signatory:6732/tz1VSUr8wwNhLAzempoch5d6hLRiTh8Cjcjb"
	BobSignatoryURL      = "http://signatory:6732/tz1aSkwEot3L2kmUvcoxzjMomb9mvBNuzFK6"
	OpstestSignatoryURL  = "http://signatory:6732/tz1RKGhRF4TZNCXEfwyqZshGsVfrZeVU446B"
	Opstest1SignatoryURL = "http://signatory:6732/tz1R8HJMzVdZ9RqLCknxeq9w5rSbiqJ41szi"

	// Address type test accounts signatory URLs
	Tz1AliasSignatoryURL = "http://signatory:6732/tz1dSrM2D7XcWPhdZpDxzNkmVLvdWSxApXaR"
	Tz2AliasSignatoryURL = "http://signatory:6732/tz2QPsZoZse4eeahhg5DdfnBDB4VbU1PwgxN"
	Tz3AliasSignatoryURL = "http://signatory:6732/tz3ZbCsUveF3Q6WUNkThT1wyJyhPunanaAXK"
	Tz4AliasSignatoryURL = "http://signatory:6732/tz4XXtsYav3fZz2FSDa7hcx4F8sh8SaDWNME"

	Tz4PopSignatoryURL = "http://signatory:6732/tz4Eb1d5L4njHViVgDDkas7qNgoZgDw6VYPz"
)

// Account aliases used in tests
const (
	AliceAlias    = "alice"
	AuthAlias     = "auth"
	BakerAlias    = "baker"
	Baker1Alias   = "baker1"
	BobAlias      = "bob"
	OpstestAlias  = "opstest"
	Opstest1Alias = "opstest1"
	Tz1Alias      = "tz1alias"
	Tz2Alias      = "tz2alias"
	Tz3Alias      = "tz3alias"
	Tz4Alias      = "tz4alias"
	Tz4PopAlias   = "tz4pop"
)

// Structured access to keys using structs
type PublicKeyHash struct{}

func (PublicKeyHash) Alice() string    { return AlicePKH }
func (PublicKeyHash) Bob() string      { return BobPKH }
func (PublicKeyHash) Opstest() string  { return OpstestPKH }
func (PublicKeyHash) Opstest1() string { return Opstest1PKH }
func (PublicKeyHash) Baker() string    { return BakerPKH }
func (PublicKeyHash) Baker1() string   { return Baker1PKH }
func (PublicKeyHash) AuthTest() string { return AuthTestPKH }
func (PublicKeyHash) Tz1Alias() string { return Tz1AliasPKH }
func (PublicKeyHash) Tz2Alias() string { return Tz2AliasPKH }
func (PublicKeyHash) Tz3Alias() string { return Tz3AliasPKH }
func (PublicKeyHash) Tz4Alias() string { return Tz4AliasPKH }
func (PublicKeyHash) Tz4Pop() string   { return Tz4PopPKH }

type PublicKey struct{}

func (PublicKey) Alice() string    { return AlicePK }
func (PublicKey) Bob() string      { return BobPK }
func (PublicKey) Opstest() string  { return OpstestPK }
func (PublicKey) Opstest1() string { return Opstest1PK }
func (PublicKey) Tz1Alias() string { return Tz1AliasPK }
func (PublicKey) Tz2Alias() string { return Tz2AliasPK }
func (PublicKey) Tz3Alias() string { return Tz3AliasPK }
func (PublicKey) Tz4Alias() string { return Tz4AliasPK }
func (PublicKey) Tz4Pop() string   { return Tz4PopPK }

type SecretKey struct{}

func (SecretKey) Alice() string    { return AliceSK }
func (SecretKey) Bob() string      { return BobSK }
func (SecretKey) Opstest() string  { return OpstestSK }
func (SecretKey) Opstest1() string { return Opstest1SK }
func (SecretKey) Baker() string    { return BakerSK }
func (SecretKey) Tz1Alias() string { return Tz1AliasSK }
func (SecretKey) Tz2Alias() string { return Tz2AliasSK }
func (SecretKey) Tz3Alias() string { return Tz3AliasSK }
func (SecretKey) Tz4Alias() string { return Tz4AliasSK }
func (SecretKey) Tz4Pop() string   { return Tz4PopSK }
func (SecretKey) Auth() string     { return AuthKeySK }

type SignatoryURL struct{}

func (SignatoryURL) Alice() string    { return AliceSignatoryURL }
func (SignatoryURL) Bob() string      { return BobSignatoryURL }
func (SignatoryURL) Opstest() string  { return OpstestSignatoryURL }
func (SignatoryURL) Opstest1() string { return Opstest1SignatoryURL }
func (SignatoryURL) Tz1Alias() string { return Tz1AliasSignatoryURL }
func (SignatoryURL) Tz2Alias() string { return Tz2AliasSignatoryURL }
func (SignatoryURL) Tz3Alias() string { return Tz3AliasSignatoryURL }
func (SignatoryURL) Tz4Alias() string { return Tz4AliasSignatoryURL }
func (SignatoryURL) Tz4Pop() string   { return Tz4PopSignatoryURL }

// Global instances for easy access
var (
	PKH = PublicKeyHash{}
	PK  = PublicKey{}
	SK  = SecretKey{}
	URL = SignatoryURL{}
)

// GetPKHByAlias returns the public key hash for a given alias
func GetPKHByAlias(alias string) string {
	switch alias {
	case AliceAlias:
		return AlicePKH
	case BobAlias:
		return BobPKH
	case OpstestAlias:
		return OpstestPKH
	case Opstest1Alias:
		return Opstest1PKH
	case BakerAlias:
		return BakerPKH
	case Baker1Alias:
		return Baker1PKH
	case Tz1Alias:
		return Tz1AliasPKH
	case Tz2Alias:
		return Tz2AliasPKH
	case Tz3Alias:
		return Tz3AliasPKH
	case Tz4Alias:
		return Tz4AliasPKH
	case Tz4PopAlias:
		return Tz4PopPKH
	default:
		return ""
	}
}

// GetPKByAlias returns the public key for a given alias
func GetPKByAlias(alias string) string {
	switch alias {
	case AliceAlias:
		return AlicePK
	case BobAlias:
		return BobPK
	case OpstestAlias:
		return OpstestPK
	case Opstest1Alias:
		return Opstest1PK
	case Tz1Alias:
		return Tz1AliasPK
	case Tz2Alias:
		return Tz2AliasPK
	case Tz3Alias:
		return Tz3AliasPK
	case Tz4Alias:
		return Tz4AliasPK
	case Tz4PopAlias:
		return Tz4PopPK
	default:
		return ""
	}
}

// GetSignatoryURLByAlias returns the signatory URL for a given alias
func GetSignatoryURLByAlias(alias string) string {
	switch alias {
	case AliceAlias:
		return AliceSignatoryURL
	case BobAlias:
		return BobSignatoryURL
	case OpstestAlias:
		return OpstestSignatoryURL
	case Opstest1Alias:
		return Opstest1SignatoryURL
	case Tz1Alias:
		return Tz1AliasSignatoryURL
	case Tz2Alias:
		return Tz2AliasSignatoryURL
	case Tz3Alias:
		return Tz3AliasSignatoryURL
	case Tz4Alias:
		return Tz4AliasSignatoryURL
	case Tz4PopAlias:
		return Tz4PopSignatoryURL
	default:
		return ""
	}
}

// GetAllTestPKHs returns all public key hashes used in tests
func GetAllTestPKHs() []string {
	return []string{
		AlicePKH,
		BobPKH,
		OpstestPKH,
		Opstest1PKH,
		Tz1AliasPKH,
		Tz2AliasPKH,
		Tz3AliasPKH,
		Tz4AliasPKH,
		Tz4PopPKH,
	}
}

// GetAllTestPKs returns all public keys used in tests
func GetAllTestPKs() []string {
	return []string{
		AlicePK,
		BobPK,
		OpstestPK,
		Opstest1PK,
		Tz1AliasPK,
		Tz2AliasPK,
		Tz3AliasPK,
		Tz4AliasPK,
		Tz4PopPK,
	}
}

// GetAllTestAliases returns all account aliases used in tests
func GetAllTestAliases() []string {
	return []string{
		AliceAlias,
		BobAlias,
		OpstestAlias,
		Opstest1Alias,
		Tz1Alias,
		Tz2Alias,
		Tz3Alias,
		Tz4Alias,
		Tz4PopAlias,
	}
}
