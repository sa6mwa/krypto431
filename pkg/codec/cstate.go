package codec

import "fmt"

type cState struct {
	alt   bool
	shift bool
	hex   bool
}

func (s *cState) modifyAndGetBytes(new cState) []byte {
	var out []byte
	if (new.shift && !s.shift) || (!new.shift && s.shift) {
		if !s.alt {
			out = append(out, SwitchTableCh)
			s.alt = true
		}
		out = append(out, ShiftModeCh)
		s.shift = new.shift
	}
	if (new.hex && !s.hex) || (!new.hex && s.hex) {
		if !s.alt {
			out = append(out, SwitchTableCh)
			s.alt = true
		}
		out = append(out, HexModeCh)
		s.hex = new.hex
	}
	if (new.alt && !s.alt) || (!new.alt && s.alt) {
		out = append(out, SwitchTableCh)
		s.alt = new.alt
	}
	return out
}

func (s *cState) setFromBytes(p []byte) {
	for _, b := range p {
		switch b {
		case SwitchTableCh:
			s.alt = !s.alt
			continue
		}
		if s.alt {
			switch b {
			case HexModeCh:
				s.hex = !s.hex
				continue
			case ShiftModeCh:
				s.shift = !s.shift
				continue
			}
		}
	}
}

func (s cState) String() string {
	return fmt.Sprintf("[Alt: %t, Shift: %t, Hex: %t]", s.alt, s.shift, s.hex)
}
