package ledger

import (
	"errors"
	"fmt"
)

// DeviceInfo contains device enumeration result
type DeviceInfo struct {
	Path       string
	DeviceInfo *LedgerDeviceInfo
}

// Exchanger is an interface implemented by an transport's abstract device
type Exchanger interface {
	Exchange(req *APDUCommand) (*APDUResponse, error)
	Close() error
}

// Transport represents transport backend such as USB HID or BLE
type Transport interface {
	Enumerate() ([]*DeviceInfo, error)
	Open(path string) (Exchanger, error)
}

// App implements global commands available regardless of the running application
type App struct {
	Exchanger
}

// Version contains application version info
type Version struct {
	Name    string
	Version string
	Flags   int
}

func (v *Version) String() string {
	return fmt.Sprintf("%s %s / %#x", v.Name, v.Version, v.Flags)
}

const claGlobal = 0xb0

const (
	insVersion = 0x01
	insQuit    = 0xa7
)

var errMsgUnexpectedEnd = errors.New("unexpected end of the message")

func getByte(buf *[]byte) (b byte, err error) {
	if len(*buf) < 1 {
		return 0, errMsgUnexpectedEnd
	}
	b = (*buf)[0]
	*buf = (*buf)[1:]
	return b, nil
}

func getBytes(buf *[]byte, ln int) (b []byte, err error) {
	if len(*buf) < ln {
		return nil, errMsgUnexpectedEnd
	}
	b = (*buf)[:ln]
	*buf = (*buf)[ln:]
	return b, nil
}

// GetAppVersion returns running app version
func (a *App) GetAppVersion() (*Version, error) {
	res, err := a.Exchange(&APDUCommand{
		Cla: claGlobal,
		Ins: insVersion,
	})
	if err != nil {
		return nil, err
	}
	if res.SW != APDUStatusOk {
		return nil, APDUError(res.SW)
	}

	d := res.Data
	f, err := getByte(&d)
	if err != nil {
		return nil, err
	}
	if f != 1 {
		return nil, fmt.Errorf("invalid version info format: %d", f)
	}
	ln, err := getByte(&d)
	if err != nil {
		return nil, err
	}
	name, err := getBytes(&d, int(ln))
	if err != nil {
		return nil, err
	}
	ln, err = getByte(&d)
	if err != nil {
		return nil, err
	}
	version, err := getBytes(&d, int(ln))
	if err != nil {
		return nil, err
	}
	ln, err = getByte(&d)
	if err != nil {
		return nil, err
	}
	fbuf, err := getBytes(&d, int(ln))
	if err != nil {
		return nil, err
	}

	var flags int
	for _, v := range fbuf {
		flags = (flags << 8) | int(v)
	}
	return &Version{
		Name:    string(name),
		Version: string(version),
		Flags:   flags,
	}, nil
}

// QuitApp commands Ledger to close currently running application
func (a *App) QuitApp() error {
	res, err := a.Exchange(&APDUCommand{
		Cla: claGlobal,
		Ins: insQuit,
	})
	if err != nil {
		return err
	}
	if res.SW != APDUStatusOk {
		return APDUError(res.SW)
	}
	return nil
}
