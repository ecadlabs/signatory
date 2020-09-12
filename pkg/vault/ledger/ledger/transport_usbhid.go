package ledger

import (
	"errors"
	"fmt"
	"math/rand"
	"runtime"
	"time"

	"github.com/karalabe/hid"
)

const (
	ledgerUSBVendorID = 0x2c97
	ledgerUsagePage   = 0xffa0
	headerSize        = 5
	packetSize        = 64
	chunkSize         = packetSize - headerSize
)

const (
	cmdPing = 2
	cmdAPDU = 5
)

// USBHIDTransport is a USB HID transport backend
type USBHIDTransport struct{}

func isValidInterface(d *hid.DeviceInfo) bool {
	if runtime.GOOS == "darwin" || runtime.GOOS == "windows" {
		return d.UsagePage == ledgerUsagePage
	}
	return d.Interface == 0
}

// Enumerate returns a list os attached Ledger devices
func (u *USBHIDTransport) Enumerate() ([]*DeviceInfo, error) {
	devs := hid.Enumerate(ledgerUSBVendorID, 0)
	res := make([]*DeviceInfo, 0, len(devs))
	for _, d := range devs {
		if !isValidInterface(&d) {
			continue
		}

		di := DeviceInfo{
			Path: d.Path,
		}
		for _, ldi := range ledgerDevices {
			if ldi.LegacyUSBProductID == d.ProductID || ldi.ProductIDMM == uint8((d.ProductID>>8)&0xff) {
				di.DeviceInfo = ldi
				break
			}
		}
		res = append(res, &di)
	}

	return res, nil
}

type usbHIDRoundTripper struct {
	channel uint16
	dev     *hid.Device
}

type packet struct {
	channel uint16
	cmd     uint8
	seq     uint16
	data    []byte
}

func (u *usbHIDRoundTripper) writePacket(p *packet) error {
	var pkt [packetSize]byte
	pkt[0] = uint8((p.channel >> 8) & 0xff)
	pkt[1] = uint8(p.channel & 0xff)
	pkt[2] = p.cmd
	pkt[3] = uint8((p.seq >> 8) & 0xff)
	pkt[4] = uint8(p.seq & 0xff)
	copy(pkt[5:], p.data)
	if _, err := u.dev.Write(pkt[:]); err != nil {
		return fmt.Errorf("ledger: %w", err)
	}
	return nil
}

func (u *usbHIDRoundTripper) readPacket() (*packet, error) {
	var pkt [packetSize]byte
	sz, err := u.dev.Read(pkt[:])
	if err != nil {
		return nil, fmt.Errorf("ledger: %w", err)
	}
	var pl = pkt[:sz]
	if len(pl) < 5 {
		return nil, fmt.Errorf("ledger: packet is too short: %d", sz)
	}
	return &packet{
		channel: uint16(pl[0])<<8 | uint16(pl[1]),
		cmd:     pl[2],
		seq:     uint16(pl[3])<<8 | uint16(pl[4]),
		data:    pkt[5:],
	}, nil
}

func (u *usbHIDRoundTripper) writeCommand(cmd uint8, data []byte) error {
	pkt := packet{
		channel: u.channel,
		cmd:     cmd,
	}
	if cmd != cmdAPDU {
		return u.writePacket(&pkt)
	}

	off := 0
	buf := make([]byte, len(data)+2)
	buf[0] = uint8((len(data) >> 8) & 0xff)
	buf[1] = uint8(len(data) & 0xff)
	copy(buf[2:], data)

	numPackets := (len(buf) + chunkSize - 1) / chunkSize
	for i := 0; i < numPackets; i++ {
		pkt.seq = uint16(i)
		pkt.data = buf[off:]
		off += chunkSize
		if err := u.writePacket(&pkt); err != nil {
			return err
		}
	}
	return nil
}

func (u *usbHIDRoundTripper) readCommand() (channel uint16, cmd uint8, data []byte, err error) {
	var (
		dataLen int
		idx     uint16
	)
	data = make([]byte, 0)
	for {
		var pkt *packet
		pkt, err = u.readPacket()
		if err != nil {
			return
		}
		pl := pkt.data
		if idx == 0 {
			cmd = pkt.cmd
			channel = pkt.channel
			if cmd == cmdAPDU {
				if len(pl) < 2 {
					err = fmt.Errorf("ledger: packet is too short: %d", len(pl))
					return
				}
				dataLen = int(pl[0])<<8 | int(pl[1])
				pl = pl[2:]
			}
		}
		// subsequent packages must have the same channel and command ids
		if pkt.seq != idx {
			err = fmt.Errorf("ledger: invalid packet index: %d", pkt.seq)
			return
		}
		if pkt.cmd != cmd {
			err = fmt.Errorf("ledger: unexpected command: %d", pkt.cmd)
			return
		}
		if pkt.channel != channel {
			err = fmt.Errorf("ledger: unexpected channel: %d", pkt.channel)
			return
		}
		ln := len(pl)
		if ln > dataLen-len(data) {
			ln = dataLen - len(data)
		}
		data = append(data, pl[:ln]...)
		idx++

		if len(data) == dataLen {
			return
		}
	}
}

func (u *usbHIDRoundTripper) Exchange(req *APDUCommand) (*APDUResponse, error) {
	r := req.Bytes()
	if err := u.writeCommand(cmdAPDU, r); err != nil {
		return nil, err
	}
	ch, cmd, data, err := u.readCommand()
	if err != nil {
		return nil, err
	}
	if ch != u.channel {
		return nil, fmt.Errorf("ledger: invalid channel in reply: %d", ch)
	}
	if cmd != cmdAPDU {
		return nil, fmt.Errorf("ledger: invalid command: %d", cmd)
	}
	apdu := parseAPDUResponse(data)
	if apdu == nil {
		return nil, errors.New("ledger: error parsing APDU response")
	}
	return apdu, nil
}

func (u *usbHIDRoundTripper) Ping() error {
	if err := u.writeCommand(cmdPing, nil); err != nil {
		return err
	}
	ch, cmd, data, err := u.readCommand()
	if err != nil {
		return err
	}
	if cmd == cmdPing {
		if ch != u.channel {
			return fmt.Errorf("ledger: invalid channel in reply: %d", ch)
		}
		return nil
	} else if cmd == cmdAPDU {
		apdu := parseAPDUResponse(data)
		if apdu == nil {
			return errors.New("ledger: error parsing APDU response")
		}
		return APDUError(apdu.SW)
	}
	return fmt.Errorf("ledger: invalid command: %d", cmd)
}

func (u *usbHIDRoundTripper) Close() error {
	return u.dev.Close()
}

// Open returns a new Exchanger
func (u *USBHIDTransport) Open(path string) (Exchanger, error) {
	if path == "" {
		devs, err := u.Enumerate()
		if err != nil {
			return nil, err
		}
		if len(devs) == 0 {
			return nil, errors.New("ledger: no Ledger devices found")
		}
		path = devs[0].Path
	}

	dev, err := hid.DeviceInfo{Path: path}.Open()
	if err != nil {
		return nil, fmt.Errorf("ledger: %w", err)
	}

	rt := usbHIDRoundTripper{
		dev:     dev,
		channel: uint16(rand.Int31n(1 << 16)),
	}

	return &rt, nil
}

func init() {
	rand.Seed(time.Now().UnixNano())
}

var _ Transport = &USBHIDTransport{}
