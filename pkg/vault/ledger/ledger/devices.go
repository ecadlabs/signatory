package ledger

import (
	"github.com/google/uuid"
)

// BluetoothSpec represents BLE services
type BluetoothSpec struct {
	ServiceUUID uuid.UUID
	NotifyUUID  uuid.UUID
	WriteUUID   uuid.UUID
}

// LedgerDeviceInfo contains some hardcoded device information picked by the product ID
// https://github.com/LedgerHQ/ledgerjs/blob/master/packages/devices/src/index.js
type LedgerDeviceInfo struct {
	ID                 string
	ProductName        string
	ProductIDMM        uint8
	LegacyUSBProductID uint16
	USBOnly            bool
	MemorySize         int
	BlockSize          int
	BluetoothSpec      []*BluetoothSpec
}

var ledgerDevices = []*LedgerDeviceInfo{
	&LedgerDeviceInfo{
		ID:                 "blue",
		ProductName:        "Ledger Blue",
		ProductIDMM:        0x00,
		LegacyUSBProductID: 0x0000,
		USBOnly:            true,
		MemorySize:         480 * 1024,
		BlockSize:          4 * 1024,
	},
	&LedgerDeviceInfo{
		ID:                 "nanoS",
		ProductName:        "Ledger Nano S",
		ProductIDMM:        0x10,
		LegacyUSBProductID: 0x0001,
		USBOnly:            true,
		MemorySize:         320 * 1024,
		BlockSize:          4 * 1024,
	},
	&LedgerDeviceInfo{
		ID:                 "nanoX",
		ProductName:        "Ledger Nano X",
		ProductIDMM:        0x40,
		LegacyUSBProductID: 0x0004,
		USBOnly:            false,
		MemorySize:         2 * 1024 * 1024,
		BlockSize:          4 * 1024,
		BluetoothSpec: []*BluetoothSpec{
			{
				ServiceUUID: uuid.MustParse("13d63400-2c97-0004-0000-4c6564676572"),
				NotifyUUID:  uuid.MustParse("13d63400-2c97-0004-0001-4c6564676572"),
				WriteUUID:   uuid.MustParse("13d63400-2c97-0004-0002-4c6564676572"),
			},
		},
	},
}
