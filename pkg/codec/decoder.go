package codec

import (
	"fmt"

	"github.com/sa6mwa/krypto431/pkg/kenc"
)

type Decoder struct {
	dec       decodeState
	curMsg    *ReceivedMessage
	msgC      chan *ReceivedMessage
	decrypter kenc.Decrypter
	curKey    string
}

type decodeState struct {
	isAlt   bool
	isShift bool
	isHex   bool
	isKey   bool
}

// NewDecoder creates a new decoder that decodes an encoded data stream
func NewDecoder(decrypter kenc.Decrypter) *Decoder {
	m := Decoder{
		msgC:      make(chan *ReceivedMessage),
		decrypter: decrypter,
	}
	return &m
}

// MsgC returns the message channel where decoded messages are received
func (m *Decoder) MsgC() chan *ReceivedMessage {
	return m.msgC
}

// Write writes data into the decoder so they can be processed
func (m *Decoder) Write(p []byte) (int, error) {
	decBuf := make([]byte, 1)
loop:
	for _, b := range p {
		if b < 'A' || b > 'Z' {
			continue
		}

		if m.decrypter != nil && m.curKey != "" {
			// Decrypt byte
			_, err := m.decrypter.Write([]byte{b})
			if err != nil {
				return 0, fmt.Errorf("decrypt write error: %w", err)
			}
			_, err = m.decrypter.Read(decBuf)
			if err != nil {
				return 0, fmt.Errorf("decrypt read error: %w", err)
			}
			b = decBuf[0]
		}

		if m.curMsg != nil && m.curMsg.isSectionMode() {
			m.curMsg.setSection(Section(b))
			continue
		}

		if m.dec.isHex && b >= 'A' && b <= 'P' {
			m.curMsg.appendHex(b)
			continue
		}

		if b == SwitchTableCh {
			m.dec.isAlt = !m.dec.isAlt
			continue
		}

		// Special bytes handling
		if m.dec.isAlt {
			switch b {
			case HexModeCh:
				m.dec.isHex = !m.dec.isHex
				err := m.curMsg.setHexMode()
				if err != nil {
					return 0, err
				}
				continue
			case ShiftModeCh:
				m.dec.isShift = !m.dec.isShift
				continue
			}
			if m.dec.isShift {
				switch b {
				case EndOfMessageCh:
					err := m.curMsg.close()
					m.curMsg = nil
					if err != nil {
						return 0, fmt.Errorf("error closing message: %w", err)
					}
					continue
				case EndOfTransmissionCh:
					m.dec = decodeState{}
					if m.curMsg != nil {
						err := m.curMsg.close()
						m.curMsg = nil
						if err != nil {
							return 0, fmt.Errorf("error closing message: %w", err)
						}
					}
					break loop
				}
			}
		}

		if m.curMsg == nil {
			m.curMsg = newReceivedMessage()
			m.msgC <- m.curMsg
		}

		table := ""
		if m.dec.isAlt {
			if m.dec.isShift {
				table = CharTableBL
			} else {
				table = CharTableBU
			}
		} else {
			if m.dec.isShift {
				table = CharTableAL
			} else {
				table = CharTableAU
			}
		}

		if m.dec.isAlt {
			switch b {
			case KeyModeCh:
				m.dec.isKey = !m.dec.isKey
				isKeyMode := m.curMsg.toggleKeyMode()
				if !isKeyMode && m.decrypter != nil {
					m.curKey = m.curMsg.getCurKey()
					_, err := m.decrypter.OpenKey(m.curKey)
					if err != nil {
						return 0, fmt.Errorf("error opening key '%s': %w", m.curKey, err)
					}
				}
				continue
			}
			if m.dec.isShift {
				switch b {
				case SectionSelectCh:
					m.curMsg.setSectionMode()
					continue
				case BellCh:
					m.curMsg.append('\a')
					continue
				case TabCh:
					m.curMsg.append('\t')
					continue
				case Reserved1Ch, Reserved2Ch, Reserved3Ch, Reserved4Ch:
					continue
				default:
					m.curMsg.append([]byte(string([]rune(table)[b-'A']))...)
					continue
				}
			} else {
				m.curMsg.append([]byte(string([]rune(table)[b-'A']))...)
				continue
			}
		} else {
			if m.dec.isShift {
				switch b {
				case NewLineCh:
					m.curMsg.append('\n')
					continue
				default:
					m.curMsg.append([]byte(string([]rune(table)[b-'A']))...)
					continue
				}
			} else {
				m.curMsg.append([]byte(string([]rune(table)[b-'A']))...)
				continue
			}
		}
	}
	if m.curMsg != nil {
		err := m.curMsg.flush()
		if err != nil {
			return 0, fmt.Errorf("flush error: %w", err)
		}
	}

	return len(p), nil
}

// Close closes the decoder
func (m *Decoder) Close() error {
	defer close(m.msgC)
	if m.curMsg != nil {
		err := m.curMsg.close()
		if err != nil {
			return err
		}
	}
	return nil
}

func decodeHex(msg []byte) ([]byte, error) {
	l := len(msg)
	if l%2 != 0 {
		return nil, fmt.Errorf("uneven byte count")
	}
	ret := make([]byte, l/2)
	var j int
	for i := 0; i < l; i += 2 {
		b1 := msg[i] - 'A'
		b2 := msg[i+1] - 'A'
		if b1 >= 16 || b2 >= 16 {
			return nil, fmt.Errorf("invalid byte range (%s, %s)", string(msg[i]), string(msg[i+1]))
		}
		ret[j] = (b1 << 4) | b2
		j++
	}
	return ret, nil
}
