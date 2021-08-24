package ledger

import (
	"fmt"
)

// Well known APDU status codes
const (
	APDUStatusOk = 0x9000
)

// APDUCommand represents parsed APDU (doesn't fully conform to ISO7816-4)
type APDUCommand struct {
	Cla     uint8
	Ins     uint8
	P1      uint8
	P2      uint8
	Data    []byte
	Raw     []byte
	ForceLc bool // Some applications (i.e. Tezos) might require Lc byte even if the data length is zero
}

// Bytes returns packed APDU
func (a *APDUCommand) Bytes() []byte {
	if a.Raw != nil {
		return a.Raw
	}
	buf := make([]byte, 4, 5+len(a.Data))
	buf[0] = a.Cla
	buf[1] = a.Ins
	buf[2] = a.P1
	buf[3] = a.P2
	if a.ForceLc || len(a.Data) != 0 {
		buf = append(buf, uint8(len(a.Data)&0xff))
	}
	buf = append(buf, a.Data...)
	return buf
}

// APDUResponse represents APDU response
type APDUResponse struct {
	Data []byte
	SW   uint16
}

func parseAPDUResponse(buf []byte) *APDUResponse {
	if len(buf) < 2 {
		return nil
	}
	return &APDUResponse{
		Data: buf[:len(buf)-2],
		SW:   uint16(buf[len(buf)-2])<<8 | uint16(buf[len(buf)-1]),
	}
}

// APDUError represents bare numeric APDU status code
type APDUError uint16

func (a APDUError) Error() string {
	return fmt.Sprintf("ledger: APDU %#04x", uint16(a))
}
