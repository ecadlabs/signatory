package tezosapp

import (
	"fmt"
)

const (
	claTezos = 0x80
)

const (
	insVersion = iota
	insAuthorizeBaking
	insGetPublicKey
	insPromptPublicKey
	insSign
	insSignUnsafe // Data that is already hashed.
	insReset
	insQueryAuthKey
	insQueryMainHWM
	insGit
	insSetup
	insQueryAllHWM
	insDeauthorize
	insQueryAuthKeyWithCurve
	insHMAC
	insSignWithHash
)

const (
	errIncorrectLength             = 0x6700
	errIncompatibleFileStructure   = 0x6981
	errSecurityStatusUnsatisfied   = 0x6982
	errHidRequired                 = 0x6983
	errConditionsOfUseNotSatisfied = 0x6985
	errIncorrectData               = 0x6a80
	errFileNotFound                = 0x9404
	errParseError                  = 0x9405
	errIncorrectParams             = 0x6b00
	errIncorrectLengthLe           = 0x6c00
	errInsNotSupported             = 0x6d00
	errIncorrectClass              = 0x6e00
	errOk                          = 0x9000
	errIncorrectLengthForIns       = 0x917e
	errMemoryError                 = 0x9200
	errReferencedDataNotFound      = 0x6a88
)

var errDesc = map[uint16]string{
	errIncorrectLength:             "Incorrect length",
	errIncompatibleFileStructure:   "Incompatible file structure",
	errSecurityStatusUnsatisfied:   "Security status unsatisfied",
	errHidRequired:                 "HID required",
	errConditionsOfUseNotSatisfied: "Conditions of use not satisfied",
	errIncorrectData:               "Incorrect data",
	errFileNotFound:                "File not found",
	errParseError:                  "Parse error",
	errIncorrectParams:             "Incorrect params",
	errIncorrectLengthLe:           "Incorrect length",
	errInsNotSupported:             "Ins not supported",
	errIncorrectClass:              "Incorrect class",
	errOk:                          "Ok",
	errIncorrectLengthForIns:       "Incorrect length for ins",
	errMemoryError:                 "Memory error",
	errReferencedDataNotFound:      "Referenced data not found",
}

// TezosError represents the Tezos specific subset of APDU status codes
type TezosError uint16

func (l TezosError) Error() string {
	if desc, ok := errDesc[uint16(l)]; ok {
		return fmt.Sprintf("[%#04x]: %s", l, desc)
	} else if l&0xfff0 == 0x63c0 {
		return fmt.Sprintf("[%#04x]: Invalid pin %d", l, l&0xf)
	} else if l&0xff00 == 0x6f00 {
		return fmt.Sprintf("[%#04x]: Technical problem %d", l, l&0xff)
	}
	return fmt.Sprintf("[%#04x]: Unknown error", l)
}
