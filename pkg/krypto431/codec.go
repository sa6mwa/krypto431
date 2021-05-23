package krypto431

var (
	CharTableAU []byte = []byte(`ABCDEFGHIJKLMNOP RSTUVWXY_`)
	CharTableAL []byte = []byte(`abcdefghijklmnop_rstuvwxy_`)
	CharTableBU []byte = []byte(`0123456789ÅÄÖÆØ.Q?Z+-,____`)
	CharTableBL []byte = []byte(`__________åäöæø:q!z"/%____`)
)

const (
	DummyCh             byte = '_'
	NewLineCh           byte = 'Q' // Table A shifted
	BinModeCh           byte = 'W' // Table B
	ShiftModeCh         byte = 'X' // Table B shifted & un-shifted
	KeyModeCh           byte = 'Y' // Table B
	SwitchTableCh       byte = 'Z' // Table A/B
	ResetAllCh          byte = 'A' // Table B shifted
	BellCh              byte = 'B' // Table B shifted
	TabCh               byte = 'C' // Table B shifted
	BackspaceCh         byte = 'D' // Table B shifted
	EndOfTransmissionCh byte = 'E' // Table B shifted
	DataModeCh          byte = 'F' // Table B shifted
	Reserved1Ch         byte = 'G' // Table B shifted
	Reserved2Ch         byte = 'H' // Table B shifted
	Reserved3Ch         byte = 'I' // Table B shifted
	Reserved4Ch         byte = 'J' // Table B shifted
	Reserved5Ch         byte = 'W' // Table B shifted
	Reserved6Ch         byte = 'Y' // Table B shifted
)

// Format of a data block
// The transmission starts with a DataModeCh (TableB shifted F)
// The transmission is divided into two parts. The header and the binary data
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
// Written out: |F IMAGE.JPG T IMAGE/JPEG C CRC32|BINDATA|102345678
