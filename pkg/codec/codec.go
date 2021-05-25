package codec

import "fmt"

var (
	ErrInvalidMsgData = fmt.Errorf("invalid msg data, only A-Z allowed")
)

const chunkLen = 5

const CharTableAU = `ABCDEFGHIJKLMNOP RSTUVWXY_`
const CharTableAL = `abcdefghijklmnop_rstuvwxy_`
const CharTableBU = `0123456789ÅÄÖÆØ.Q?Z+-,____`
const CharTableBL = `__________åäöæø:q!z"/%____`
const DummyCh = '_'

const (
	SectionSelectCh     = 'A' // Table B shifted - Section selector
	BellCh              = 'B' // Table B shifted - Audible signal
	TabCh               = 'C' // Table B shifted - Tab (8 spaces)
	Reserved1Ch         = 'D' // Table B shifted
	EndOfMessageCh      = 'E' // Table B shifted - End of message
	EndOfTransmissionCh = 'F' // Table B shifted - End of transmission
	Reserved2Ch         = 'G' // Table B shifted
	Reserved3Ch         = 'H' // Table B shifted
	Reserved4Ch         = 'I' // Table B shifted
	Reserved5Ch         = 'J' // Table B shifted
	NewLineCh           = 'Q' // Table A shifted - \n
	HexModeCh           = 'W' // Table B shifted / un-shifted  - HEX mode
	ShiftModeCh         = 'X' // Table B shifted / un-shifted  - Shift switch
	KeyModeCh           = 'Y' // Table B shifted / un-shifted  - Key name mode
	SwitchTableCh       = 'Z' // Table A/B shifted / un-sifted - Table switch
)

type Section byte

// A section is a special part of a message that is different from the normal
// message data
const (
	// SectionDefault - Default message data
	SectionDefault = Section(0)
	// SectionChecksum - CRC32 checksum of all data that came before
	SectionChecksum = Section('C')
	// SectionHeader - Header section with key value pairs of metadata
	SectionHeader = Section('H')
)

/*
* How to transfer generic data
* To create a data transfer start your message with a header that defines the
* content type (CT). The content type can be either a file extension (without
* the dot) or a well known mime type.
* Then send the data in hex mode.
* Optionally it is also recommended to add a CRC32 checksum to the message
 */

func validate(msg []byte) error {
	for i, b := range msg {
		if b < 'A' || b > 'Z' {
			return fmt.Errorf("unsupported numeric value at index; %d", i)
		}
	}
	return nil
}

func formatChunks(msg string) string {
	padLen := 0
	mod := len(msg) % chunkLen
	if mod != 0 {
		padLen = chunkLen - mod
	}
	for i := 0; i < padLen; i++ {
		msg += "Z"
	}
	return insertNth(msg, chunkLen, " ")
}

func insertNth(str string, n int, ins string) string {
	var ret string
	l := len(str)
	for i, r := range str {
		ret += string(r)
		if i%n == n-1 && i < l-1 {
			ret += ins
		}
	}
	return ret
}

func runeIndex(s string, r rune) int {
	for i, rc := range []rune(s) {
		if r == rc {
			return i
		}
	}
	return -1
}
