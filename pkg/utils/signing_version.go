package utils

// SigningVersion represents the version of signing being used
type SigningVersion uint8

const (
	// SigningVersion0 represents Signing version 0
	SigningVersion0 SigningVersion = 0
	// SigningVersion1 represents Signing version 1
	SigningVersion1 SigningVersion = 1
	// SigningVersion2 represents Signing version 2
	SigningVersion2 SigningVersion = 2
	// SigningVersionLatest represents the latest Signing version
	SigningVersionLatest SigningVersion = SigningVersion2
)

// IsValid checks if the SigningVersion is valid
func (v SigningVersion) IsValid() bool {
	return v == SigningVersion1 || v == SigningVersion2
}

// ToUint8 converts SigningVersion to uint8 for compatibility with existing code
func (v SigningVersion) ToUint8() uint8 {
	return uint8(v)
}

// FromString parses a string and returns the corresponding SigningVersion and a bool indicating success.
func ParseVersionString(s string) SigningVersion {
	switch s {
	case "0":
		return SigningVersion0
	case "1":
		return SigningVersion1
	case "2":
		return SigningVersion2
	case "":
		return SigningVersionLatest
	default:
		return SigningVersionLatest
	}
}
