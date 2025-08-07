package utils

// BlsKeyVersion represents the version of BLS key being used
type BlsKeyVersion uint8

const (
	// BlsVersion0 represents BLS version 0
	BlsVersion0 BlsKeyVersion = 0
	// BlsVersion1 represents BLS version 1
	BlsVersion1 BlsKeyVersion = 1
	// BlsVersion2 represents BLS version 2
	BlsVersion2 BlsKeyVersion = 2
	// BlsVersionLatest represents the latest BLS version
	BlsVersionLatest BlsKeyVersion = BlsVersion2
)

// IsValid checks if the BLS key version is valid
func (v BlsKeyVersion) IsValid() bool {
	return v == BlsVersion1 || v == BlsVersion2
}

// ToUint8 converts BlsKeyVersion to uint8 for compatibility with existing code
func (v BlsKeyVersion) ToUint8() uint8 {
	return uint8(v)
}

// FromString parses a string and returns the corresponding BlsKeyVersion and a bool indicating success.
func ParseVersionString(s string) BlsKeyVersion {
	switch s {
	case "0":
		return BlsVersion0
	case "1":
		return BlsVersion1
	case "2":
		return BlsVersion2
	case "":
		return BlsVersionLatest
	default:
		return BlsVersionLatest
	}
}
