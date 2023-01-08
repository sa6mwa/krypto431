package codec

import (
	"fmt"

	"github.com/sa6mwa/krypto431/pkg/kenc"
)

type Decoder struct {
	state     cState
	curMsg    *ReceivedMessage
	msgC      chan *ReceivedMessage
	decrypter kenc.Decrypter
	curKey    string
}

// NewDecoder creates a new decoder that decodes an encoded data stream
// An optional decrypter can be supplied if the stream is encrypted
func NewDecoder(decrypter kenc.Decrypter) *Decoder {
	d := Decoder{
		msgC:      make(chan *ReceivedMessage),
		decrypter: decrypter,
	}
	return &d
}

// MsgC returns the message channel where decoded messages are received
func (d *Decoder) MsgC() chan *ReceivedMessage {
	return d.msgC
}

// Write writes data into the decoder so they can be processed
func (d *Decoder) Write(p []byte) (int, error) {
	decBuf := make([]byte, 1)
	for _, b := range p {
		if b < 'A' || b > 'Z' {
			continue
		}

		if d.decrypter != nil && d.curKey != "" {
			// Decrypt byte
			_, err := d.decrypter.Write([]byte{b})
			if err != nil {
				return 0, fmt.Errorf("decrypt write error: %w", err)
			}
			_, err = d.decrypter.Read(decBuf)
			if err != nil {
				return 0, fmt.Errorf("decrypt read error: %w", err)
			}
			b = decBuf[0]
		}

		if d.curMsg != nil && d.curMsg.isSectionMode() {
			d.curMsg.setSection(Section(b))
			continue
		}

		if d.state.hex && b >= 'A' && b <= 'P' {
			d.curMsg.appendHex(b)
			continue
		}

		if b == SwitchTableCh {
			d.state.alt = !d.state.alt
			continue
		}

		// Special bytes handling
		if d.state.alt {
			switch b {
			case HexModeCh:
				d.state.hex = !d.state.hex
				err := d.curMsg.setHexMode()
				if err != nil {
					return 0, err
				}
				continue
			case ShiftModeCh:
				d.state.shift = !d.state.shift
				continue
			}
			if d.state.shift {
				switch b {
				case EndOfMessageCh:
					err := d.curMsg.close()
					d.curMsg = nil
					if err != nil {
						return 0, fmt.Errorf("error closing message: %w", err)
					}
					continue
				case EndOfTransmissionCh:
					d.state = cState{}
					if d.curMsg != nil {
						err := d.curMsg.close()
						d.curMsg = nil
						if err != nil {
							return 0, fmt.Errorf("error closing message: %w", err)
						}
					}
					continue
				}
			}
		}

		if d.curMsg == nil {
			d.curMsg = newReceivedMessage()
			d.msgC <- d.curMsg
		}

		table := ""
		if d.state.alt {
			if d.state.shift {
				table = CharTableBL
			} else {
				table = CharTableBU
			}
		} else {
			if d.state.shift {
				table = CharTableAL
			} else {
				table = CharTableAU
			}
		}

		if d.state.alt {
			switch b {
			case KeyModeCh:
				isKeyMode := d.curMsg.toggleKeyMode()
				if !isKeyMode && d.decrypter != nil {
					d.curKey = d.curMsg.getCurKey()
					_, err := d.decrypter.OpenKey(d.curKey)
					if err != nil {
						return 0, fmt.Errorf("error opening key '%s': %w", d.curKey, err)
					}
				}
				continue
			}
			if d.state.shift {
				switch b {
				case SectionSelectCh:
					d.curMsg.setSectionMode()
					continue
				case BellCh:
					d.curMsg.append('\a')
					continue
				case TabCh:
					d.curMsg.append('\t')
					continue
				case Reserved1Ch, Reserved2Ch, Reserved3Ch, Reserved4Ch, Reserved5Ch:
					continue
				default:
					d.curMsg.append([]byte(string([]rune(table)[b-'A']))...)
					continue
				}
			} else {
				d.curMsg.append([]byte(string([]rune(table)[b-'A']))...)
				continue
			}
		} else {
			if d.state.shift {
				switch b {
				case NewLineCh:
					d.curMsg.append('\n')
					continue
				default:
					d.curMsg.append([]byte(string([]rune(table)[b-'A']))...)
					continue
				}
			} else {
				d.curMsg.append([]byte(string([]rune(table)[b-'A']))...)
				continue
			}
		}
	}
	if d.curMsg != nil {
		err := d.curMsg.flush()
		if err != nil {
			return 0, fmt.Errorf("flush error: %w", err)
		}
	}

	return len(p), nil
}

// Close closes the decoder
func (d *Decoder) Close() error {
	defer close(d.msgC)
	if d.curMsg != nil {
		err := d.curMsg.close()
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
