package codec

import (
	"errors"
	"fmt"
	"io"

	"github.com/sa6mwa/krypto431/pkg/kenc"
	"github.com/sa6mwa/krypto431/pkg/keystore"
)

const reservedKeyLen = 16

type Encoder struct {
	section      Section
	w            io.Writer
	encrypter    kenc.Encrypter
	curKey       keystore.Key
	encState     cState
	writeState   cState
	noEndMarkers bool
	msgCount     int
}

var ErrMaxOneMessage = errors.New("max one message allowed when using no end markers")

// NewEncoder creates a new encoder that can encode messages to the output
// writer (w). An optional encrypter can be used to encrypt the stream
func NewEncoder(w io.Writer, encrypter kenc.Encrypter) *Encoder {
	e := Encoder{
		w:         w,
		encrypter: encrypter,
	}
	return &e
}

func (e *Encoder) WithNoEndMarkers() *Encoder {
	e.noEndMarkers = true
	return e
}

// NewMessage creates a new message to send
func (e *Encoder) NewMessage() (*MessageWriter, error) {
	if e.noEndMarkers && e.msgCount >= 1 {
		return nil, ErrMaxOneMessage
	}
	e.msgCount++
	return &MessageWriter{
		Header:       Header{},
		encoder:      e,
		noEndMarkers: e.noEndMarkers,
	}, nil
}

// Close closes the encoder and send an optional EndOfTransmission
func (e *Encoder) Close() error {
	if !e.noEndMarkers {
		_ = e.endOfTransmission()
	}
	return nil
}

// setSection sets the section type
func (e *Encoder) setSection(section Section) error {
	prevSection := e.section
	out := e.encState.modifyAndGetBytes(cState{true, true, false})
	out = append(out, SectionSelectCh)
	if section != prevSection && section != 0 {
		out = append(out, byte(section))
	}
	e.section = section
	_, err := e.write(out)
	return err
}

// endOfMessage appends an EndOfMessage indicator in the stream
func (e *Encoder) endOfMessage() error {
	out := e.encState.modifyAndGetBytes(cState{true, true, false})
	out = append(out, EndOfMessageCh)
	_, err := e.write(out)
	return err
}

// endOfTransmission send an EndOfTransmission indicator in the stream
func (e *Encoder) endOfTransmission() error {
	out := e.encState.modifyAndGetBytes(cState{true, true, false})
	out = append(out, EndOfTransmissionCh)
	_, err := e.write(out)
	return err

}

// encodeString encodes a UTF-8 string into the stream
func (e *Encoder) encodeString(msg string) error {
	out, err := e.encodeStringToBuf(&e.encState, msg)
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
func (e *Encoder) encodeStringToBuf(state *cState, msg string) ([]byte, error) {
	var out []byte
	for _, r := range msg {
		var ch rune = DummyCh
		var idx int
		var err error
		var stateBuf []byte
		if idx = runeIndex(CharTableAU, r); idx >= 0 {
			stateBuf = state.modifyAndGetBytes(cState{false, false, false})
			ch = []rune(CharTableAU)[idx]
		} else if idx = runeIndex(CharTableAL, r); idx >= 0 {
			stateBuf = state.modifyAndGetBytes(cState{false, true, false})
			ch = []rune(CharTableAU)[idx]
		} else if idx = runeIndex(CharTableBU, r); idx >= 0 {
			stateBuf = state.modifyAndGetBytes(cState{true, false, false})
			ch = []rune(CharTableAU)[idx]
		} else if idx = runeIndex(CharTableBL, r); idx >= 0 {
			stateBuf = state.modifyAndGetBytes(cState{true, true, false})
			ch = []rune(CharTableAU)[idx]
		}
		out = append(out, stateBuf...)
		if idx >= 0 && ch != DummyCh {
			out = append(out, byte(idx)+'A')
			continue
		}
		switch r {
		case '\n':
			stateBuf = state.modifyAndGetBytes(cState{false, true, false})
			out = append(out, stateBuf...)
			out = append(out, NewLineCh)
			continue
		case '\a':
			stateBuf = state.modifyAndGetBytes(cState{true, true, false})
			out = append(out, stateBuf...)
			out = append(out, BellCh)
			continue
		case '\t':
			stateBuf = state.modifyAndGetBytes(cState{true, true, false})
			out = append(out, stateBuf...)
			out = append(out, TabCh)
			continue
		}
		stateBuf = state.modifyAndGetBytes(cState{true, state.shift, true})
		out = append(out, stateBuf...)
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
	out := e.encState.modifyAndGetBytes(cState{true, e.encState.shift, true})
	ebs, err := encodeHex(p)
	if err != nil {
		return err
	}
	out = append(out, ebs...)
	_, err = e.write(out)
	return err
}

func (e *Encoder) write(p []byte) (int, error) {
	var err error
	if e.encrypter != nil {
		// We have an encrypter, so we pass the data thru it
		if e.curKey == nil {
			// First time we don't have a key (in the beginning of the stream)
			// So we need to save the key name to the stream (un-encrypted)
			e.curKey, err = e.encrypter.GetNextKey()
			if err != nil {
				return 0, fmt.Errorf("error getting next key: %w", err)
			}
			e.curKey, err = e.encrypter.OpenKey(e.curKey.Name())
			if err != nil {
				return 0, fmt.Errorf("error opening key: %w", err)
			}
			keyOut, err := e.getKeyBuf()
			if err != nil {
				return 0, err
			}
			_, err = e.w.Write(keyOut)
			if err != nil {
				return 0, fmt.Errorf("key write error: %w", err)
			}
			// After the key name is written we start writing encrypted data
			// right away. This first data is to reset the state to the start
			// condition
			stateBuf := e.writeState.modifyAndGetBytes(cState{false, false, false})
			_, err = e.encrypter.Write(stateBuf)
			if err != nil {
				return 0, fmt.Errorf("write error: %w", err)
			}
		}

		bytesWritten := 0
		writeBytesLeft := len(p)
		for writeBytesLeft > 0 {
			if e.curKey.BytesLeft() <= reservedKeyLen {
				// We need to change to the next key since there are only
				// a few bytes left in this key
				e.curKey, err = e.encrypter.GetNextKey()
				if err != nil {
					return 0, fmt.Errorf("error getting next key: %w", err)
				}
				oldState := e.writeState
				keyOut, err := e.getKeyBuf()
				if err != nil {
					return 0, err
				}
				if len(keyOut) > reservedKeyLen {
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
				// Get the bytes needed to reset the stream state, but don't
				// modify the writeState. This is because the writeState will
				// be set in the setFromBytes() function later
				temp := e.writeState
				stateBuf := temp.modifyAndGetBytes(oldState)
				p = append(stateBuf, p...) // prepend the state bytes
				writeBytesLeft += len(stateBuf)
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

// getKeyBuf returns an encoded key byte sequence to be written to the stream
func (e *Encoder) getKeyBuf() ([]byte, error) {
	keyOut := e.writeState.modifyAndGetBytes(cState{true, e.writeState.shift, false})
	keyOut = append(keyOut, KeyModeCh) // begin key mode
	keyData, err := e.encodeStringToBuf(&e.writeState, e.curKey.Name())
	if err != nil {
		return nil, fmt.Errorf("encode error: %w", err)
	}
	keyOut = append(keyOut, keyData...)
	stateBuf := e.writeState.modifyAndGetBytes(cState{true, e.writeState.shift, false})
	keyOut = append(keyOut, stateBuf...)
	keyOut = append(keyOut, KeyModeCh) // end key mode
	return keyOut, nil
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
