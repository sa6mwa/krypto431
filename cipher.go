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
	// X in 2nd = switch case (toggle case like CAPS LOCK)
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

func toLower(c *rune, b *rune) {
	var diff rune = 'a' - 'A'
	if *c >= 'A' && *c <= 'Z' {
		*b = *c + diff
	} else {
		*b = *c
	}
	return
}

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
	// keylength = 100*300 = 30000 characters/runes/bytes).
	// TODO: Add warning when slice capacity is about to be reached.
	*slice = append(*slice, *r)
}

/*
func (state *codecState) reset(p *Message) error {
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

func (state *codecState) nextTable(output *[]rune) {
	state.table = (state.table + 1) % state.numberOfTables
	if output != nil {
		*output = append(*output, nextTableChar)
	}
}

func (state *codecState) toggleCase(output *[]rune) error {
	if output != nil {
		err := state.gotoTable(secondaryTable, output)
		if err != nil {
			return err
		}
		*output = append(*output, caseToggleChar)
		//t.EncodedText = append(t.EncodedText, caseToggleChar)
		//appendRune(&t.EncodedText, *caseToggleChar)
	}
	state.shift = !state.shift
	return nil
}

func (state *codecState) toggleBinary(output *[]rune) error {
	if output != nil {
		err := state.gotoTable(secondaryTable, output)
		if err != nil {
			return err
		}
		*output = append(*output, binaryToggleChar)
		//t.EncodedText = append(t.EncodedText, binaryToggleChar)
		//appendRune(&p.EncodedText, *binaryToggleChar)
	}
	state.binary = !state.binary
	return nil
}

// gotoTable takes you to a specific table while also adding nextTableChar to
// a PlainText EncodedText field. It will not write anything to the output if
// you are already on the specific table according to the state.
func (state *codecState) gotoTable(table int, output *[]rune) error {
	if table < 0 || table >= state.numberOfTables {
		return fmt.Errorf("table number out of range: %d not between 0 and %d", table, state.numberOfTables)
	}
	if state.table == table {
		// we are already in the requested table, return
		return nil
	}
	/* 	if table == primaryTable && state.table == secondaryTable && !state.binary && !state.shift {
		// ...we can use the resetAll character
		err := state.reset(t)
		if err != nil {
			return err
		}
		return nil
	} */
	for {
		if table == state.table {
			break
		}
		state.nextTable(output)
	}
	return nil
}

// encodeCharacter figures out which character sequence to write into the
// EncodedText field of a PlainText struct and adjust the state. When the first
// rune that can not be found in one of the tables appear, we switch to binary
// mode and will not exit this mode unless reaching the end or running out of
// key runes (where it will switch to the next key).
func (state *codecState) encodeCharacter(input *rune, output *[]rune) error {
	if !state.binary {
		if (isUpper(input) && state.shift) || (isLower(input) && !state.shift) {
			// need to shift/unshift...
			err := state.toggleCase(output)
			if err != nil {
				return err
			}
		}
		// find character in one of the tables
		c := *input
		toUpper(&c, &c)
		foundIt := false
		for t := range CharacterTables {
			for i, tc := range CharacterTables[t] {
				if tc == specialOpChar {
					// specialOpChar is not part of any character table, skip it
					continue
				}
				if c == tc {
					foundIt = true
					err := state.gotoTable(t, output)
					if err != nil {
						return err
					}
					char := rune(i) + rune('A')
					*output = append(*output, char)
					char = 0
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

func (state *codecState) decodeCharacter(input *rune, output *[]rune) error {
	if !state.binary {
	} else {
		panic("binary mode not implemented yet")
	}
	return nil
}

// Encode codes the PlainText field into the EncodedText field of a Message
// struct. Encode will prepend one star (*) in the beginning and add a key
// change if the message is more than Instance.KeyLength (minus characters
// needed to make a key change) long and add a star (*) as a placeholder for a
// key. In order to encrypt this encoded message you need to have key(s) of the
// correct length available in the database or encryption will fail.
func (t *Message) Encode() *[]rune {
	state := newState()

	encodedText := make([]rune, 0, len(t.PlainText)*2)

	x := 0
	for i := range t.PlainText {
		// if x >= KeyLength-GroupSize-2, add star for key-change and reset x to 0
		err := state.encodeCharacter(&t.PlainText[i], &encodedText)
		if err != nil {
			Wipe(&encodedText)
			return nil
		}
		x++
	}
	//continue here
	return &encodedText
}

/* // Decode decodes the EncodedText field into the PlainText field of a Message struct
func (t *Message) Decode() error {
	Wipe(&t.PlainText)
	state := newState()
	decodedText := make([]rune, 0, len(t.EncodedText))
	for i := range t.EncodedText {
		err := state.decodeCharacter(&t.EncodedText[i], &decodedText)
		if err != nil {
			return err
		}
	}
	t.PlainText = decodedText
	Wipe(&decodedText)
	return nil
}
*/

// EnrichWithKey finds the first appropriate key for this Message structure where
// each of the Messages Recipients are Keepers of the same key. It returns a
// pointer to the key bytes/runes that will be used by diana.Trigraph later. It
// also returns error in case no key was found or other error occurred.
func (t *Message) EnrichWithKey() (*[]rune, error) {
	if len(t.PlainText) == 0 {
		return nil, errors.New("PlainText is empty")
	}
	if len(t.KeyId) > 0 {
		// already enriched with a KeyId, check if it's used, if so, return error otherwise OK
		for i := range t.instance.Keys {
			if string(t.instance.Keys[i].Id) == string(t.KeyId) && t.instance.Keys[i].Used == true {
				return nil, fmt.Errorf("message already enriched with used KeyId %s", string(t.KeyId))
			} else if string(t.instance.Keys[i].Id) == string(t.KeyId) && t.instance.Keys[i].Used == false {
				return &t.instance.Keys[i].Id, nil
			}
		}
		return nil, errors.New("message enriched with non-existant key")
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
		if t.instance.Keys[i].Used {
			continue
		}
		if AllNeedlesInHaystack(&t.Recipients, &t.instance.Keys[i].Keepers) {
			// Found a key
			// Mark the key as Used
			t.instance.Keys[i].Used = true
			// if !Decrypt, decrypt the key
			// copy Key.Id to Message.KeyId
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

// Encipher enciphers the PlainText field into the CipherText field of a Message
// structure and wipes the PlainText field. Verbs like encrypt and decrypt are
// only used for AES-256 encryption/decryption of fields in the json savefile
// (and to encrypt the json output file itself), while words encipher and
// decipher are used for message ciphering in Krypto431.
func (t *Message) Encipher() error {
	//keyPtr, err := t.EnrichWithKey()
	_, err := t.EnrichWithKey()
	if err != nil {
		return err
	}
	// keyPtr is assumed not to be nil, at least that is the design of EnrichWithKey

	Wipe(&t.CipherText)
	state := newState()

	encodedText := make([]rune, 0, len(t.PlainText)*2)
	defer Wipe(&encodedText)

	x := 0
	//keysNeeded := 1
	for i := range t.PlainText {
		// if x >= KeyLength-GroupSize-2, add star for key-change and reset x to 0
		err := state.encodeCharacter(&t.PlainText[i], &encodedText)
		if err != nil {
			return err
		}
		x++
	}

	// encipher() encodedText with key

	//continue here

	return nil

}
