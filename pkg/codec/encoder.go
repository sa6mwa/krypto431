package codec

import (
	"fmt"
	"io"

	"github.com/sa6mwa/krypto431/pkg/kenc"
	"github.com/sa6mwa/krypto431/pkg/keystore"
)

const chunkLen = 5
const reservedKeyLen = 16

type Encoder struct {
	enc        encoderState
	section    Section
	w          io.Writer
	encrypter  kenc.Encrypter
	curKey     keystore.Key
	writeState encoderState
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
	out, err := e.encodeStringToBuf(&e.enc, msg)
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
func (e *Encoder) encodeStringToBuf(state *encoderState, msg string) ([]byte, error) {
	var out []byte
	for _, r := range msg {
		var ch rune = DummyCh
		var idx int
		var err error
		var altsOut []byte
		if idx = runeIndex(CharTableAU, r); idx >= 0 {
			altsOut = state.modifyAndGetBytes(encoderState{false, false, false})
			//altsOut = e.applyEncAlts(false, false, false)
			ch = []rune(CharTableAU)[idx]
		} else if idx = runeIndex(CharTableAL, r); idx >= 0 {
			//altsOut = e.applyEncAlts(false, true, false)
			altsOut = state.modifyAndGetBytes(encoderState{false, true, false})
			ch = []rune(CharTableAU)[idx]
		} else if idx = runeIndex(CharTableBU, r); idx >= 0 {
			//altsOut = e.applyEncAlts(true, false, false)
			altsOut = state.modifyAndGetBytes(encoderState{true, false, false})
			ch = []rune(CharTableAU)[idx]
		} else if idx = runeIndex(CharTableBL, r); idx >= 0 {
			//altsOut = e.applyEncAlts(true, true, false)
			altsOut = state.modifyAndGetBytes(encoderState{true, true, false})
			ch = []rune(CharTableAU)[idx]
		}
		out = append(out, altsOut...)
		if idx >= 0 && ch != DummyCh {
			out = append(out, byte(idx)+'A')
			continue
		}
		switch r {
		case '\n':
			//altsOut = e.applyEncAlts(false, true, false)
			altsOut = state.modifyAndGetBytes(encoderState{false, true, false})
			out = append(out, altsOut...)
			out = append(out, NewLineCh)
			continue
		case '\a':
			//altsOut = e.applyEncAlts(true, true, false)
			altsOut = state.modifyAndGetBytes(encoderState{true, true, false})
			out = append(out, altsOut...)
			out = append(out, BellCh)
			continue
		case '\t':
			//altsOut = e.applyEncAlts(true, true, false)
			altsOut = state.modifyAndGetBytes(encoderState{true, true, false})
			out = append(out, altsOut...)
			out = append(out, TabCh)
			continue
		}
		//altsOut = e.applyEncAlts(true, e.enc.isShift, true)
		altsOut = state.modifyAndGetBytes(encoderState{true, state.isShift, true})
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
		if e.curKey == nil {
			// First time we don't have a key (in the beginning of the stream)
			e.curKey, err = e.encrypter.GetNextKey()
			if err != nil {
				return 0, fmt.Errorf("error getting next key: %w", err)
			}
			e.curKey, err = e.encrypter.OpenKey(e.curKey.Name())
			if err != nil {
				return 0, fmt.Errorf("error opening key: %w", err)
			}
			// First time we write the key un-encrypted

			keyOut := e.writeState.modifyAndGetBytes(encoderState{true, false, false})
			keyOut = append(keyOut, KeyModeCh) // begin
			keyData, err := e.encodeStringToBuf(&e.writeState, e.curKey.Name())
			if err != nil {
				return 0, fmt.Errorf("encode error: %w", err)
			}
			keyOut = append(keyOut, keyData...)
			alts := e.writeState.modifyAndGetBytes(encoderState{true, e.writeState.isShift, false})
			keyOut = append(keyOut, alts...)
			keyOut = append(keyOut, KeyModeCh) // end
			// Reset the state to the start state
			_, err = e.w.Write(keyOut)
			if err != nil {
				return 0, fmt.Errorf("key write error: %w", err)
			}
			alts = e.writeState.modifyAndGetBytes(encoderState{false, false, false})
			_, err = e.encrypter.Write(alts)
			if err != nil {
				return 0, fmt.Errorf("write error: %w", err)
			}
		}

		bytesWritten := 0
		writeBytesLeft := len(p)
		for writeBytesLeft > 0 {
			if e.curKey.BytesLeft() <= reservedKeyLen {
				e.curKey, err = e.encrypter.GetNextKey()
				if err != nil {
					return 0, fmt.Errorf("error getting next key: %w", err)
				}
				oldState := e.writeState
				keyOut := e.writeState.modifyAndGetBytes(encoderState{true, e.writeState.isShift, false})
				keyOut = append(keyOut, KeyModeCh) // begin
				keyData, err := e.encodeStringToBuf(&e.writeState, e.curKey.Name())
				if err != nil {
					return 0, fmt.Errorf("encode error: %w", err)
				}
				keyOut = append(keyOut, keyData...)
				alts := e.writeState.modifyAndGetBytes(encoderState{true, e.writeState.isShift, false})
				keyOut = append(keyOut, alts...)
				keyOut = append(keyOut, KeyModeCh) // end
				keyOutLen := len(keyOut)
				if keyOutLen > reservedKeyLen {
					return 0, fmt.Errorf("reserved key length too short to write next key name")
				}
				_, err = e.encrypter.Write(keyOut)
				if err != nil {
					return 0, fmt.Errorf("write error: %w", err)
				}
				e.curKey, err = e.encrypter.OpenKey(e.curKey.Name())
				if err != nil {
					return 0, fmt.Errorf("error opening key: %w", err)
				}
				temp := e.writeState
				alts = temp.modifyAndGetBytes(oldState)
				p = append(alts, p...)
				writeBytesLeft += len(alts)
			}
			writeSize := minInt(writeBytesLeft, e.curKey.BytesLeft()-reservedKeyLen)
			writeP := p[:writeSize]
			e.writeState.setFromBytes(writeP)
			n, err := e.encrypter.Write(writeP)
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
