package krypto

import (
	"errors"
	"fmt"
)

var (
	// CharacterTablePrimary is the initial character table
	CharacterTablePrimary []rune = []rune(`ABCDEFGHIJKLMNOP RSTUVWXY~`)
	// CharacterTableSecondary is the 2nd (previously alternate) character table
	CharacterTableSecondary []rune = []rune(`0123456789ÅÄÖÆØ~Q~Z~~~~~~~`)
	// CharacterTableTertiary is the 3rd character table
	CharacterTableTertiary []rune = []rune(`{}:,\[]"?!@#%&*.?_/+-=~~~~`)
	// CharacterTables is a slice of all character tables (this is what the code use)
	CharacterTables [][]rune = [][]rune{
		CharacterTablePrimary, CharacterTableSecondary, CharacterTableTertiary,
	}
)

const (
	primaryTable   int = 0
	secondaryTable int = 1
	tertiaryTable  int = 2
)

const (
	// specialOpChar was dummyChar, means character has special meaning, see below...
	// specialOpChar will be replaced by zeroes during initialization (0x00)
	specialOpChar rune = '~'

	// caseToggleChar adds strings.ToLower() on every character depending on previous
	// state (stateShift).
	caseToggleChar rune = 'V'

	// binaryModeChar changes into a binary-only mode where A-P is one nibble
	// (meaning that 1 rune is 2 characters). To exit the binary mode, issue W
	// again and you return to the secondary character table in the non-binary
	// mode.
	binaryToggleChar rune = 'W'

	// resetAllChar re-initializes everything and goes back to the primary
	// character table, resetAllChar is (so far) in both the primary and the
	// secondary character table.
	resetAllChar rune = 'X'

	// changeKeyChar instructs that immediately after this character is the key
	// id (always 1 group) to change to. After the key (1 group) has been
	// changed, the state is reset starting at the primary group un-shifted.
	changeKeyChar rune = 'Y'

	// nextTableChar switches to the next table (if 3 table, then mod(3))
	nextTableChar rune = 'Z'

	// I to R, T, U, V, W, and Y are so far reserved in the third character table
	// (X and Z have the same meaning as in the secondary table)

	// Note on section change: ZUUX (change to secondary table, ==, reset) can be
	// used to separate one section from the other (header from message from
	// footer section for example). This is the same
)

func isUpper(c *rune) bool {
	if *c >= 'A' && *c <= 'Z' {
		return true
	}
	return false
}

func isLower(c *rune) bool {
	if *c >= 'a' && *c <= 'z' {
		return true
	}
	return false
}

/*
func isLetter(c rune) bool {
	if isUpper(c) || isLower(c) {
		return true
	}
	return false
}
*/

func toUpper(c *rune) {
	var diff rune = 'a' - 'A'
	if *c >= 'a' && *c <= 'z' {
		*b = *c - diff
	} else {
		*b = *c
	}
	return
}

/*
func toLower(c *rune) (b rune) {
	var diff rune = 'a' - 'A'
	if *c >= 'A' && *c <= 'Z' {
		b = *c + diff
	}
	return
}
*/

type codecState struct {
	table          int
	numberOfTables int
	shift          bool
	binary         bool
	lowerNibble    bool
}

func newState() *codecState {
	return &codecState{
		table:          0,
		numberOfTables: len(CharacterTables),
		shift:          false,
		binary:         false,
		lowerNibble:    false,
	}
}

func (state *codecState) reset(p *Text) error {
	if p != nil {
		err := state.gotoTable(secondaryTable, p)
		if err != nil {
			return err
		}
		appendRune(&p.CipherText, resetAllChar)
	}
	state.table = 0
	state.numberOfTables = len(CharacterTables)
	state.shift = false
	state.binary = false
	state.lowerNibble = false
	return nil
}
func (state *codecState) nextTable(p *PlainText) {
	state.table = (state.table + 1) % state.numberOfTables
	if p != nil {
		appendByte(&p.EncodedText, nextTableChar)
	}
}
func (state *codecState) toggleCase(p *PlainText) error {
	if p != nil {
		err := state.gotoTable(secondaryTable, p)
		if err != nil {
			return err
		}
		appendByte(&p.EncodedText, caseToggleChar)
	}
	state.shift = !state.shift
	return nil
}
func (state *codecState) toggleBinary(p *PlainText) error {
	if p != nil {
		err := state.gotoTable(secondaryTable, p)
		if err != nil {
			return err
		}
		appendByte(&p.EncodedText, binaryToggleChar)
	}
	state.binary = !state.binary
	return nil
}

// gotoTable takes you to a specific table while also adding nextTableChar to
// a PlainText EncodedText field. It will not write anything to the output if
// you are already on the specific table according to the state.
func (state *codecState) gotoTable(t int, p *PlainText) error {
	if t < 0 || t >= state.numberOfTables {
		return fmt.Errorf("table number out of range: %d not between 0 and %d", t, state.numberOfTables)
	}
	if state.table == t {
		// we are already in the requested table, return
		return nil
	}
	if t == primaryTable && state.table == secondaryTable && !state.binary && !state.shift {
		// ...we can use the resetAll character
		err := state.reset(p)
		if err != nil {
			return err
		}
		return nil
	}
	for {
		if t == state.table {
			break
		}
		state.nextTable(p)
	}
	return nil
}

// encodeCharacter figures out which character sequence to write into the
// EncodedText field of a PlainText struct and adjust the state. When the first
// rune that can not be found in one of the tables appear, we switch to binary
// mode and will not exit this mode unless reaching the end or running out of
// key runes (where it will switch to the next key).
func (state *codecState) encodeCharacter(input *rune, p *PlainText) error {
	if !state.binary {
		if (isUpper(input) && state.shift) || (isLower(input) && !state.shift) {
			// need to shift/unshift...
			err := state.toggleCase(p)
			if err != nil {
				return err
			}
		}
		// find character in one of the tables
		c := *input
		toUpper(&c)
		foundIt := false
		for t := range CharacterTables {
			for i, tc := range CharacterTables[t] {
				if tc == specialOpChar {
					// specialOpChar is not part of any character table, skip it
					continue
				}
				if c == tc {
					foundIt = true
					err := state.gotoTable(t, p)
					if err != nil {
						return err
					}
					char := rune(i) + rune('A')
					appendByte(&p.EncodedText, char)
					break
				}
			}
			if foundIt {
				break
			}
		}
		// zero copy of rune
		c = 0
		if !foundIt {
			// enter binary mode
			panic("binary mode not implemented yet")
		}
	} else {
		panic("binary mode not implemented yet")
	}
	return nil
}

func (state *codecState) decodeCharacter(input *rune, p *PlainText) error {
	if !state.binary {
	} else {
		panic("binary mode not implemented yet")
	}
}

// Encode codes the Text field into the EncodedText field of a PlainText
// struct. Encode will prepend one star (*) in the beginning and add a key
// change if the message is more than Instance.KeyLength (minus characters
// needed to make a key change) long and add a star (*) as a placeholder for a
// key. In order to encrypt this encoded message you need to have key(s) of the
// correct length available in the database or encryption will fail.
func (p *PlainText) Encode() error {
	Wipe(&p.EncodedText)
	state := newState()

	for i := range p.Text {
		err := state.encodeCharacter(&p.Text[i], p)
		if err != nil {
			return err
		}
	}
	//continue here
	return nil
}

// Decode decodes the EncodedText field into the Text field of a PlainText struct
func (p *PlainText) Decode() error {
	Wipe(&p.Text)
	state := newState()

	for i := range p.EncodedText {
		err := state.decodeCharacter(&p.EncodedText[i], p)
		if err != nil {
			return err
		}
	}
	return nil
}

// Encrypt encrypts the PlainText field into the CipherText field usin of a Text
// structure and wipes the PlainText field.
func (t *Text) Encrypt(recipients *[]CallSign) error {
	if len(t.KeyId) < t.instance.GroupSize {
		return errors.New("KeyId is empty or less than GroupSize for this instance")
	}

}
