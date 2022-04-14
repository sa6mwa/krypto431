package krypto431

import (
	"errors"
	"fmt"
)

var (
	CharacterTablePrimary   []rune = []rune(`ABCDEFGHIJKLMNOP RSTUVWXY¤`)
	CharacterTableSecondary []rune = []rune(`0123456789?-ÅÄÖ.Q,Z:+/¤¤¤¤`)

	// Z = change character table
	// Q in 1st = space
	// Q in 2nd = Q
	// S in 2nd = Z
	// W in 2nd = switch to binary mode, 1 byte is 2 runes, A to P is one nibble (4 bits, 1-16)
	// X in 2nd = switch case (toggle case like capslock)
	// Y in 2nd = change key (followed by 5 character key after which the table is reset)

	//CharacterTablePrimary   []rune   = []rune(`ABCDEFGHIJKLMNOP RSTUVWXY¤`)
	//CharacterTableSecondary []rune   = []rune(`0123456789ÅÄÖÆØ¤Q¤Z¤¤¤¤¤¤¤`)
	//CharacterTableTertiary  []rune   = []rune(`{}:,\[]"?!@#%&*.?-/+_=¤¤¤¤`)
	CharacterTables [][]rune = [][]rune{
		CharacterTablePrimary, CharacterTableSecondary,
	}
)

const (
	primaryTable   int = 0
	secondaryTable int = 1
	//tertiaryTable  int = 2

	// specialOpChar was dummyChar, means character has special meaning, see below...
	// specialOpChar will be replaced by zeroes during initialization (0x00)
	specialOpChar rune = '¤'

	// caseToggleChar adds strings.ToLower() on every character depending on previous
	// state (stateShift).
	caseToggleChar rune = 'X'

	// binaryModeChar changes into a binary-only mode where A-P is one nibble
	// (meaning that 1 rune is 2 characters). To exit the binary mode, issue W
	// again and you return to the secondary character table in the non-binary
	// mode.
	binaryToggleChar rune = 'W'

	// resetAllChar re-initializes everything and goes back to the primary
	// character table, resetAllChar is (so far) in both the primary and the
	// secondary character table.
	//resetAllChar rune = 'X'

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

func toUpper(c *rune, b *rune) {
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
	keyIndex       int
	table          int
	numberOfTables int
	shift          bool
	binary         bool
	lowerNibble    bool
}

func newState() *codecState {
	return &codecState{
		keyIndex:       0,
		table:          0,
		numberOfTables: len(CharacterTables),
		shift:          false,
		binary:         false,
		lowerNibble:    false,
	}
}

func appendRune(slice *[]rune, r *rune) {
	// capacity of the underlying array should have been setup not to cause
	// reallocation (based on maximum message size length, by default 100 *
	// keylength = 100*200 = 20000 characters/runes/bytes).
	// TODO: Add warning when slice capacity is about to be reached.
	*slice = append(*slice, *r)
}

/* func (state *codecState) reset(p *Text) error {
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
*/

func (state *codecState) nextTable(t *Text) {
	state.table = (state.table + 1) % state.numberOfTables
	if t != nil {
		appendRune(&t.EncodedText, *nextTableChar)
	}
}
func (state *codecState) toggleCase(t *Text) error {
	if t != nil {
		err := state.gotoTable(secondaryTable, t)
		if err != nil {
			return err
		}
		appendRune(&t.EncodedText, *caseToggleChar)
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
		appendRune(&p.EncodedText, *binaryToggleChar)
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
func (state *codecState) encodeCharacter(input *rune, t *Text) error {
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
					appendRune(&p.EncodedText, char)
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

// EnrichWithKey finds the first appropriate key for this Text structure where
// each of the Text's Recipients are Keepers of the same key. It returns a
// pointer to the key bytes/runes that will be used by diana.Trigraph later. It
// also returns error in case no key was found or other error occurred.
func (t *Text) EnrichWithKey() (*[]rune, error) {
	if len(t.PlainText) == 0 {
		return nil, errors.New("PlainText is empty")
	}
	if len(t.KeyId) > 0 {
		return nil, errors.New("Text appear to be enriched with a KeyId already, will not continue")
	}
	if len(t.CipherText) > 0 {
		return nil, errors.New("Text appear to have CipherText already, will not enrich with key")
	}
	if len(t.Recipients) == 0 {
		return nil, errors.New("Text has no Recipients")
	}
	// Find the first key where all Recipients are Keepers
	var keyPtr *[]rune
	for i := range t.instance.Keys {
		if i.instance.Keys[i].Used {
			continue
		}
		if AllNeedlesInHaystack(&t.Recipients, &t.instance.Keys[i].Keepers) {
			// Found a key
			// Mark the key as Used
			t.instance.Keys[i].Used = true
			// if !Decrypt, decrypt the key
			// copy Key.Id to Text.KeyId
			t.KeyId = t.instance.Keys[i].Id
			keyPtr = &t.instance.Keys[i].Runes
			break
		}
	}
	if keyPtr == nil {
		return nil, errors.New("Did not find a key where all Recipients are Keepers of the same key")
	}
	if len(t.KeyId) < t.instance.GroupSize {
		return nil, errors.New("KeyId is empty or less than GroupSize")
	}
	return keyPtr, nil
}

// Encipher enciphers the PlainText field into the CipherText field of a Text
// structure and wipes the PlainText field. Verbs like encrypt and decrypt are
// only used for AES-256 encryption/decryption of fields in the json savefile
// (and to encrypt the json output file itself), while words encipher and
// decipher are used for message ciphering in Krypto431.
func (t *Text) Encipher() error {
	keyPtr, err := t.EnrichWithKey()
	if err != nil {
		return err
	}
	// keyPtr is assumed not to be nil, at least that is the design of EnrichWithKey

	Wipe(&t.CipherText)
	state := newState()

	for i := range p.PlainText {
		err := state.encodeCharacter(&t.PlainText[i], t)
		if err != nil {
			return err
		}
	}
	//continue here
	return nil

}
