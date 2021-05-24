package codec

import "fmt"

var (
	ErrInvalidMsgData = fmt.Errorf("invalid msg data, only A-Z allowed")
)

const CharTableAU = `ABCDEFGHIJKLMNOP RSTUVWXY_`
const CharTableAL = `abcdefghijklmnop_rstuvwxy_`
const CharTableBU = `0123456789ÅÄÖÆØ.Q?Z+-,____`
const CharTableBL = `__________åäöæø:q!z"/%____`
const DummyCh = '_'

const (
	NewLineCh           = 'Q' // Table A shifted              - \n
	BinModeCh           = 'W' // Table B                      - HEX mode
	ShiftModeCh         = 'X' // Table B shifted & un-shifted - Shift switch
	KeyModeCh           = 'Y' // Table B                      - Key name mode
	SwitchTableCh       = 'Z' // Table A/B                    - Table switch
	SectionSelectCh     = 'A' // Table B shifted              - Section selector
	BellCh              = 'B' // Table B shifted              - Audible signal
	TabCh               = 'C' // Table B shifted              - Tab (8 spaces)
	CheckerModeCh       = 'D' // Table B shifted              - Hash/CRC mode
	EndOfMessageCh      = 'E' // Table B shifted              - End of message
	EndOfTransmissionCh = 'F' // Table B shifted              - End of transmission
	Reserved1Ch         = 'G' // Table B shifted
	Reserved2Ch         = 'H' // Table B shifted
	Reserved3Ch         = 'I' // Table B shifted
	Reserved4Ch         = 'J' // Table B shifted
	Reserved5Ch         = 'W' // Table B shifted
	Reserved6Ch         = 'Y' // Table B shifted
)

// A section is a special part of a message that is different from the normal
// message data
const (
	SectionDefault  = 0
	SectionChecksum = 'C'
	SectionHeader   = 'H'
)

/*
Med codec kan man skapa meddelanden.
Meddelanden har en header (som kan vara tom)
Meroende på vilka inställningar man har på meddelanden så skickas det med
olika encodning

*/

const (
	// HeaderFilename, Filename of the data, if applicable:
	// Use bin mode to encode in UTF-8
	HeaderFilename = "FN"
	// HeaderContentLength, length of the data/message in bytes before encoding
	HeaderContentLength = "CL"
	// HeaderContentType, dat type of the data, usually a mime type.
	// Defaults to application/octet-stream (generic 8 bit data) if missing
	HeaderContentType = "CT"
)

// Format of a data block
// The transmission starts with a DataModeCh (TableB shifted F)
// The transmission is divided into two or three parts. The header and the
// binary data and an optional check value at the end.
// The header is defined as a list of DataField and text pairs separated by a
// space (Table A un-shifted Q)
// Example data field:
// ZXFXZ FQIMA GEZPZ JPGQT QIMAG EZXUX ZJPEG QCQCR CZDCW AAAAA AAAAA ...
// ZXFXZ = alt, shift (Table B shifted), F = data mode, shift, alt (Table A)
// FQIMA = F IMA
// GEZPZ = GE.
// JPGQT = JPG T
// QIMAG =  IMAG
// EZXUX = E/
// ZJPEG = JPEG
// QCQCR =  C CR
// CZDCW = C32 (W = bin mode)
// AAAAA = 00
// AAAAA = 000
// ...
// WBACD = 1023 (W = end of bin mode)
// EFGHI = 45678
// Written out: |F IMAGE.JPG T IMAGE/JPEG C CRC32|[BINDATA]|102345678

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
