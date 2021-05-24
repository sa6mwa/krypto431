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
	SectionSelectCh     = 'A' // Table B shifted - Section selector
	BellCh              = 'B' // Table B shifted - Audible signal
	TabCh               = 'C' // Table B shifted - Tab (8 spaces)
	CheckerModeCh       = 'D' // Table B shifted - Hash/CRC mode
	EndOfMessageCh      = 'E' // Table B shifted - End of message
	EndOfTransmissionCh = 'F' // Table B shifted - End of transmission
	Reserved1Ch         = 'G' // Table B shifted
	Reserved2Ch         = 'H' // Table B shifted
	Reserved3Ch         = 'I' // Table B shifted
	Reserved4Ch         = 'J' // Table B shifted
	NewLineCh           = 'Q' // Table A shifted - \n
	HexModeCh           = 'W' // Table B shifted / un-shifted - HEX mode
	ShiftModeCh         = 'X' // Table B shifted / un-shifted - Shift switch
	KeyModeCh           = 'Y' // Table B shifted / un-shifted - Key name mode
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

// Predefined standard headers
const (
	// HeaderFilename, Filename of the data, if applicable:
	// Use hex mode to encode in UTF-8
	HeaderFilename = "FN"
	// HeaderContentLength, length of the data/message in bytes before encoding
	HeaderContentLength = "CL"
	// HeaderContentType, data type of the data, usually a mime type, but can
	// also be a short file extension (JPG/TXT/etc).
	// Defaults to application/octet-stream (generic 8 bit data) if missing
	HeaderContentType = "CT"
	// HeaderContentEncoding defines any special encoding scheme used.
	// For example gzip
	HeaderContentEncoding = "CE"
	// HeaderTimestamp is a timestamp at which the message was orginated
	// Format is ISO 8601. Example: 2021-05-24T13:43:20Z
	// The time part can be excluded if needed
	HeaderTimestamp = "TS"
	// HeaderTimeNr is a simplified timestamp at which the message was orginated
	// Format is NNHHMM[Z] where NN is the day, HH is hour and MM is minute,
	// Z is an optional time zone code
	// If the time number is in the switch between daylight savings, use odd
	// numbers for the first hour and even numbers for the second time the
	// same hours occurres
	HeaderTimeNr = "TNR"
	// HeaderDateTimeGroup is a simplified timestamp at witch the message was orginated.
	// Format is DD HHMMZ MON YY
	// Example 1: 09 1630Z JUL 11 represents (Jul) 09 16:30 Jul 2011 (UTC).
	// Example 2: 22 0301Z May 21 represents (May) 22 03:01, May 2021 (UTC).
	HeaderDateTimeGroup = "DTG"
	// HeaderTo is a comma separated list of recipients (who should receive the message)
	HeaderTo = "TO"
	// HeaderFrom is a comma separated list of senders (who sent the message)
	HeaderFrom = "DE"
	// HeaderCc is a comma separated list of carbon copy recipients
	HeaderCc = "CC"
	// HeaderBcc is a comma separated list of blind carbon copy recipients
	HeaderBcc = "BCC"
	// HeaderPart defines that this message is part P of N parts.
	// Format is: P,N
	HeaderPart = "PART"
	// HeaderLanguage identifies the language used in this message
	// By convention use the english language name
	HeaderLanguage = "LANG"
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
