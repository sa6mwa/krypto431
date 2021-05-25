package codec

import "fmt"

type encoderState struct {
	isAlt   bool
	isShift bool
	isHex   bool
}

func (s *encoderState) modifyAndGetBytes(new encoderState) []byte {
	var out []byte
	if (new.isShift && !s.isShift) || (!new.isShift && s.isShift) {
		if !s.isAlt {
			out = append(out, SwitchTableCh)
			s.isAlt = true
		}
		out = append(out, ShiftModeCh)
		s.isShift = new.isShift
	}
	if (new.isHex && !s.isHex) || (!new.isHex && s.isHex) {
		if !s.isAlt {
			out = append(out, SwitchTableCh)
			s.isAlt = true
		}
		out = append(out, HexModeCh)
		s.isHex = new.isHex
	}
	if (new.isAlt && !s.isAlt) || (!new.isAlt && s.isAlt) {
		out = append(out, SwitchTableCh)
		s.isAlt = new.isAlt
	}
	return out
}

func (s *encoderState) setFromBytes(p []byte) {
	for _, b := range p {
		switch b {
		case SwitchTableCh:
			s.isAlt = !s.isAlt
			continue
		}
		if s.isAlt {
			switch b {
			case HexModeCh:
				s.isHex = !s.isHex
				continue
			case ShiftModeCh:
				s.isShift = !s.isShift
				continue
			}
		}
	}
}

func (s encoderState) String() string {
	return fmt.Sprintf("[Alt: %t, Shift: %t, Hex: %t]", s.isAlt, s.isShift, s.isHex)
}
