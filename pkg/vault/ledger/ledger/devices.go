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
}

var (
	ledgerBlue = LedgerDeviceInfo{
		ID:                 "blue",
		ProductName:        "Ledger Blue",
		ProductIDMM:        0x00,
		LegacyUSBProductID: 0x0000,
		USBOnly:            true,
		MemorySize:         480 * 1024,
	}
	ledgerNanoS = LedgerDeviceInfo{
		ID:                 "nanoS",
		ProductName:        "Ledger Nano S",
		ProductIDMM:        0x10,
		LegacyUSBProductID: 0x0001,
		USBOnly:            true,
		MemorySize:         320 * 1024,
	}
	ledgerNanoSP = LedgerDeviceInfo{
		ID:                 "nanoSP",
		ProductName:        "Ledger Nano S Plus",
		ProductIDMM:        0x50,
		LegacyUSBProductID: 0x0005,
		USBOnly:            true,
		MemorySize:         1536 * 1024,
	}
	ledgerNanoX = LedgerDeviceInfo{
		ID:                 "nanoX",
		ProductName:        "Ledger Nano X",
		ProductIDMM:        0x40,
		LegacyUSBProductID: 0x0004,
		USBOnly:            false,
		MemorySize:         2 * 1024 * 1024,
	}
	ledgerNanoFTS = LedgerDeviceInfo{
		ID:                 "nanoFTS",
		ProductName:        "Ledger Nano FTS",
		ProductIDMM:        0x60,
		LegacyUSBProductID: 0x0006,
		USBOnly:            false,
		MemorySize:         1536 * 1024,
	}
)

var ledgerDevices = []*LedgerDeviceInfo{
	&ledgerBlue,
	&ledgerNanoS,
	&ledgerNanoSP,
	&ledgerNanoX,
	&ledgerNanoFTS,
}
