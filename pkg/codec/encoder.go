package codec

import (
	"fmt"
	"io"

	"github.com/sa6mwa/krypto431/pkg/kenc"
	"github.com/sa6mwa/krypto431/pkg/keystore"
)

const chunkLen = 5
const reservedKeyLen = 12

type Encoder struct {
	enc       encoderState
	section   Section
	w         io.Writer
	encrypter kenc.Encrypter
	curKey    keystore.Key
}

type encoderState struct {
	isAlt   bool
	isShift bool
	isHex   bool
}

// NewEncoder creates a new encoder that can encode messages to an output stream
func NewEncoder(w io.Writer, encrypter kenc.Encrypter) *Encoder {
	e := Encoder{
		//bufC: make(chan []byte),
		w:         w,
		encrypter: encrypter,
	}
	return &e
}

// NewMessage creates a new message to send
func (e *Encoder) NewMessage() *MessageWriter {
	return &MessageWriter{
		Header:  Header{},
		encoder: e,
	}
}

// Close closes the encoder and send an optional EndOfTransmission
func (e *Encoder) Close() error {
	_ = e.endOfTransmission()
	//close(e.bufC)
	return nil
}

// Read is used to read the encoded data from the encoder
/*func (e *Encoder) Read(p []byte) (int, error) {
	if len(e.curBuf) == 0 {
		var ok bool
		e.curBuf, ok = <-e.bufC
		if !ok {
			return 0, io.EOF
		}
	}
	n := copy(p, e.curBuf)
	e.curBuf = e.curBuf[n:]
	return n, nil
}*/

// setSection sets the section type
func (e *Encoder) setSection(section Section) error {
	prevSection := e.section
	out := e.applyEncAlts(true, true, false)
	out = append(out, SectionSelectCh)
	if section != prevSection && section != 0 {
		out = append(out, byte(section))
	}
	e.section = section
	//e.bufC <- out
	_, err := e.write(out)
	return err
}

// endOfMessage appends an EndOfMessage indicator in the stream
func (e *Encoder) endOfMessage() error {
	out := e.applyEncAlts(true, true, false)
	out = append(out, EndOfMessageCh)
	//e.bufC <- out
	_, err := e.write(out)
	return err
}

// endOfTransmission send an EndOfTransmission indicator in the stream
func (e *Encoder) endOfTransmission() error {
	out := e.applyEncAlts(true, true, false)
	out = append(out, EndOfTransmissionCh)
	//e.bufC <- out
	_, err := e.write(out)
	return err

}

// encodeString encodes a UTF-8 string into the stream
func (e *Encoder) encodeString(msg string) error {
	out, err := e.encodeStringToBuf(msg)
	if err != nil {
		return err
	}
	_, err = e.write(out)
	if err != nil {
		return err
	}
	return nil
}

// encodeString encodes a UTF-8 string into the stream
func (e *Encoder) encodeStringToBuf(msg string) ([]byte, error) {
	var out []byte
	for _, r := range msg {
		var ch rune = DummyCh
		var idx int
		var err error
		var altsOut []byte
		if idx = runeIndex(CharTableAU, r); idx >= 0 {
			altsOut = e.applyEncAlts(false, false, false)
			ch = []rune(CharTableAU)[idx]
		} else if idx = runeIndex(CharTableAL, r); idx >= 0 {
			altsOut = e.applyEncAlts(false, true, false)
			ch = []rune(CharTableAU)[idx]
		} else if idx = runeIndex(CharTableBU, r); idx >= 0 {
			altsOut = e.applyEncAlts(true, false, false)
			ch = []rune(CharTableAU)[idx]
		} else if idx = runeIndex(CharTableBL, r); idx >= 0 {
			altsOut = e.applyEncAlts(true, true, false)
			ch = []rune(CharTableAU)[idx]
		}
		out = append(out, altsOut...)
		if idx >= 0 && ch != DummyCh {
			out = append(out, byte(idx)+'A')
			continue
		}
		switch r {
		case '\n':
			altsOut = e.applyEncAlts(false, true, false)
			out = append(out, altsOut...)
			out = append(out, NewLineCh)
			continue
		case '\a':
			altsOut = e.applyEncAlts(true, true, false)
			out = append(out, altsOut...)
			out = append(out, BellCh)
			continue
		case '\t':
			altsOut = e.applyEncAlts(true, true, false)
			out = append(out, altsOut...)
			out = append(out, TabCh)
			continue
		}
		altsOut = e.applyEncAlts(true, e.enc.isShift, true)
		out = append(out, altsOut...)
		bs, err := encodeHex([]byte(string(r)))
		if err != nil {
			return out, err
		}
		out = append(out, bs...)
	}
	return out, nil
}

// encodeBytes encodes a byte slice into the stream
func (e *Encoder) encodeBytes(p []byte) error {
	if len(p) == 0 {
		return nil
	}
	out := e.applyEncAlts(true, e.enc.isShift, true)
	ebs, err := encodeHex(p)
	if err != nil {
		return err
	}
	out = append(out, ebs...)
	//e.bufC <- out
	//return nil
	_, err = e.write(out)
	return err
}

// applyEncAlts makes sure the correct encoding flags are set to write
// the appropriate character table and shift modes are written
func (e *Encoder) applyEncAlts(useAltTable, useShifted, useHexMode bool) []byte {
	var out []byte
	var msg []byte
	if (useShifted && !e.enc.isShift) || (!useShifted && e.enc.isShift) {
		if !e.enc.isAlt {
			msg = append(msg, SwitchTableCh)
			e.enc.isAlt = true
		}
		msg = append(msg, ShiftModeCh)
		e.enc.isShift = useShifted
	}
	if (useHexMode && !e.enc.isHex) || (!useHexMode && e.enc.isHex) {
		if !e.enc.isAlt {
			msg = append(msg, SwitchTableCh)
			e.enc.isAlt = true
		}
		msg = append(msg, HexModeCh)
		e.enc.isHex = useHexMode
	}
	if (useAltTable && !e.enc.isAlt) || (!useAltTable && e.enc.isAlt) {
		msg = append(msg, SwitchTableCh)
		e.enc.isAlt = useAltTable
	}
	if msg != nil {
		out = append(out, msg...)
	}
	return out
}

func (e *Encoder) write(p []byte) (int, error) {
	var err error
	if e.encrypter != nil {
		bytesWritten := 0
		writeBytesLeft := len(p)

		if e.curKey == nil {
			// First time we don't have a key (in the beginning of the stream)
			e.curKey, err = e.encrypter.GetNextKey()
			if err != nil {
				return 0, fmt.Errorf("error getting next key: %w", err)
			}
			// First time we write the key un-encrypted
			oldState := e.enc
			keyOut := e.applyEncAlts(true, e.enc.isShift, false)
			keyOut = append(keyOut, KeyModeCh) // begin
			keyData, err := e.encodeStringToBuf(e.curKey.Name())
			if err != nil {
				return 0, fmt.Errorf("encode error: %w", err)
			}
			keyOut = append(keyOut, keyData...)
			alts := e.applyEncAlts(true, e.enc.isShift, false)
			keyOut = append(keyOut, alts...)
			keyOut = append(keyOut, KeyModeCh) // end
			_, err = e.w.Write(keyOut)
			if err != nil {
				return 0, fmt.Errorf("key write error: %w", err)
			}
			alts = e.applyEncAlts(oldState.isAlt, oldState.isShift, oldState.isHex)
			if len(alts) > 0 {
				p = append(alts, p...) // prepend
				writeBytesLeft += len(alts)
			}
		}

		for writeBytesLeft > 0 {
			if e.curKey.BytesLeft() <= reservedKeyLen {
				e.curKey, err = e.encrypter.GetNextKey()
				if err != nil {
					return 0, fmt.Errorf("error getting next key: %w", err)
				}
				oldState := e.enc
				keyOut := e.applyEncAlts(true, e.enc.isShift, false)
				keyOut = append(keyOut, KeyModeCh) // begin
				keyData, err := e.encodeStringToBuf(e.curKey.Name())
				if err != nil {
					return 0, fmt.Errorf("encode error: %w", err)
				}
				keyOut = append(keyOut, keyData...)
				alts := e.applyEncAlts(true, e.enc.isShift, false)
				keyOut = append(keyOut, alts...)
				keyOut = append(keyOut, KeyModeCh) // end
				alts = e.applyEncAlts(oldState.isAlt, oldState.isShift, oldState.isHex)
				keyOut = append(keyOut, alts...)
				keyOutLen := len(keyOut)
				if keyOutLen > reservedKeyLen {
					return 0, fmt.Errorf("reserved key length too short to write next key name")
				}
				p = append(keyOut, p...) // prepend
				writeBytesLeft += keyOutLen
			}
			writeSize := minInt(writeBytesLeft, e.curKey.BytesLeft()-reservedKeyLen)
			n, err := e.encrypter.Write(p[:writeSize])
			p = p[n:]
			writeBytesLeft -= n
			bytesWritten += n
			if err != nil {
				return 0, fmt.Errorf("write error: %w", err)
			}
		}
		ni64, err := io.Copy(e.w, e.encrypter)
		return int(ni64), err
	}
	return e.w.Write(p)
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func encodeHex(msg []byte) ([]byte, error) {
	l := len(msg)
	ret := make([]byte, l*2)
	var j int
	for _, b := range msg {
		ret[j] = (b >> 4) + 'A'
		ret[j+1] = (b & 0x0f) + 'A'
		j += 2
	}
	return ret, nil
}
