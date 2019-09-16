/*
Package smartcard implements a portable high-level API for communicating with smart cards.

Example:

    ctx, err := smartcard.EstablishContext()
    // handle error, if any
    defer ctx.Release()

    reader, err := ctx.WaitForCardPresent()
    // handle error, if any

    card, err := reader.Connect()
    // handle error, if any
    defer card.Disconnect()

    fmt.Printf("Card ATR: %s\n", card.ATR())
    command := SelectCommand(0xa0, 0x00, 0x00, 0x00, 0x62, 0x03, 0x01, 0xc, 0x01, 0x01)
    response, err := card.TransmitAPDU(command)
    // handle error, if any
    fmt.Printf("Response: %s\n", response)
*/
package smartcard

import (
	"bytes"
	"fmt"
)

// Some generic SW codes
const (
	AUTH_FAILED         uint16 = 0x63c0
	WRONG_LENGTH        uint16 = 0x6700
	RECORD_NOT_FOUND    uint16 = 0x6a83
	UNSUPPORTED_INS     uint16 = 0x6d00
	UNSUPPORTED_CLA     uint16 = 0x6e00
	EXCEPTION           uint16 = 0x6f00
	SUCCESS             uint16 = 0x9000
	NOT_AUTHORIZED      uint16 = 0x91ae
	INSUFFICIENT_MEMORY uint16 = 0x9210
)

type ATR []byte

// Return string form of ATR.
func (atr ATR) String() string {
	var buffer bytes.Buffer
	for _, b := range atr {
		buffer.WriteString(fmt.Sprintf("%02x", b))
	}
	return buffer.String()
}

// Transmit command APDU to the card and return response.
func (c *Card) TransmitAPDU(cmd CommandAPDU) (ResponseAPDU, error) {
	bytes, err := c.Transmit(cmd)
	if err != nil {
		return nil, err
	}
	r, err := Response(bytes)
	if err != nil {
		return nil, err
	}
	return r, nil
}

// ISO7816-4 command APDU.
type CommandAPDU []byte

// Create command APDU
// CLA, INS, P1, P2 is required
// Data is optional (nil to not send payload)
// Response of length Le is optional (0 to not require response)
func Command(cla, ins, p1, p2 byte, data []byte, le byte) CommandAPDU {
	var cmd CommandAPDU = make([]byte, 4)
	cmd[0] = cla
	cmd[1] = ins
	cmd[2] = p1
	cmd[3] = p2

	if len(data) > 0 {
		cmd = append(cmd, byte(len(data)))
		cmd = append(cmd, data...)
	}
	if le > 0 {
		cmd = append(cmd, le)
	}

	return cmd
}

// Create ISO7816-4 SELECT FILE APDU.
func SelectCommand(aid ...byte) CommandAPDU {
	return Command(0x00, 0xa4, 0x04, 0x00, aid, 0)
}

// Check if command APDU is valid
func (cmd CommandAPDU) IsValid() bool {
	cmdLen := byte(len(cmd))
	if cmdLen < 4 {
		return false
	}
	if cmdLen == 4 || cmdLen == 5 {
		return true
	}
	lc := cmd[4]
	if lc > cmdLen-5 {
		return false
	}
	if cmdLen-5 > lc+1 {
		return false
	}
	return true
}

// Return string form of APDU.
func (cmd CommandAPDU) String() string {
	if !cmd.IsValid() {
		return "Invalid APDU"
	}
	apdu := ([]byte)(cmd)
	buffer := new(bytes.Buffer)
	buffer.WriteString(fmt.Sprintf("%02X %02X %02X %02X", apdu[0], apdu[1],
		apdu[2], apdu[3]))
	if len(apdu) >= 5 {
		buffer.WriteString(fmt.Sprintf(" %02X", apdu[4]))
		if len(apdu) >= 6 {
			if len(apdu) == int(apdu[4]+5) {
				buffer.WriteString(fmt.Sprintf(" %X", apdu[5:]))
			} else {
				buffer.WriteString(fmt.Sprintf(" %X %02X", apdu[5:len(apdu)-1],
					apdu[len(apdu)-1]))
			}
		}
	}
	return buffer.String()
}

// ISO7816-4 response APDU.
type ResponseAPDU []byte

func Response(bytes []byte) (ResponseAPDU, error) {
	if len(bytes) < 2 {
		return nil, fmt.Errorf("Invalid response apdu size: %d", len(bytes))
	}
	return ResponseAPDU(bytes), nil
}

// Return 16-bit status word.
func (r ResponseAPDU) SW() uint16 {
	return uint16(r.SW1())<<8 | uint16(r.SW2())
}

// Return SW1
func (r ResponseAPDU) SW1() uint8 {
	return r[len(r)-2]
}

// Return SW2
func (r ResponseAPDU) SW2() uint8 {
	return r[len(r)-1]
}

// Return data part of response
func (r ResponseAPDU) Data() []byte {
	if len(r) <= 2 {
		return nil
	}
	return r[:len(r)-2]
}

// Return string form of APDU.
func (r ResponseAPDU) String() string {
	var bytes []byte = r
	if len(r) <= 2 {
		return fmt.Sprintf("%X", bytes)
	}
	return fmt.Sprintf("%X %X", bytes[:len(bytes)-2], bytes[len(bytes)-2:])
}
