package krypto431

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"unicode"

	"github.com/sa6mwa/krypto431/diana"
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

	// Encoding uses two character tables (primary and secondary). NB! Any changes
	// to the control characters in these tables need to be reflected in functions
	// encodeCharacter() and decodeCharacter().
	// CharacterTablePrimary = `ABCDEFGHIJKLMNOP RSTUVWXY¤`,
	// CharacterTableSecondary = `0123456789?-ÅÄÖ.Q,Z:+/¤¤¤¤`
	//
	// CODING LEGEND                    ⎘ Switch table (Z)
	// IDX ABCDEFGHIJKLMNOPQRSTUVWXYZ   ⬔ Toggle binary mode (W)
	// CT1 ABCDEFGHIJKLMNOP RSTUVWXY⎘   ↕ Toggle case (X)
	// CT2 0123456789?-ÅÄÖ.Q,Z:+/⬔↕⌥⎘   ⌥ Change key (Y)
	CharacterTables [][]rune = [][]rune{
		CharacterTablePrimary, CharacterTableSecondary,
	}
)

const (
	primaryTable   int = 0
	secondaryTable int = 1

	// specialOpChar (was dummyChar) means character has special meaning (a
	// control character).
	specialOpChar rune = '¤'

	// binaryModeChar changes into a binary-only mode where A-P is one nibble
	// (meaning that 1 rune is 2 characters). To exit the binary mode, put W again
	// and you return to the secondary character table in the non-binary mode.
	binaryToggleChar rune = 'W'

	// caseToggleChar adds strings.ToLower() on every character depending on previous
	// state (stateShift).
	caseToggleChar rune = 'X'

	// changeKeyChar instructs that immediately after this character is the key
	// id (always 1 group) to change to. After the key (1 group) has been
	// changed, the state is reset starting at the primary group un-shifted.
	changeKeyChar rune = 'Y'

	// nextTableChar switches to the next table (3 tables, then mod(3))
	nextTableChar rune = 'Z'

	// spaceChar is not a control character, just the rune to represent space.
	spaceChar rune = ' '

	// How many control runes/characters are required to change key at most?
	// (change table, then changeKeyChar = 2)
	ControlCharactersNeededToChangeKey int = 2
)

func isUpper(c *rune) bool {
	return unicode.IsUpper(*c)
}

func isLower(c *rune) bool {
	return unicode.IsLower(*c)
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
	*b = unicode.ToUpper(*c)
}

func toLower(c *rune, b *rune) {
	*b = unicode.ToLower(*c)
}

type codecState struct {
	keyIndex         int
	table            int
	numberOfTables   int
	charCounter      int
	gotChangeKeyChar bool
	keyChange        bool
	shift            bool
	binary           bool
	lowerNibble      bool
}

func newState() *codecState {
	return &codecState{
		keyIndex:         0,
		table:            0,
		numberOfTables:   len(CharacterTables),
		charCounter:      0,
		gotChangeKeyChar: false,
		keyChange:        false,
		shift:            false,
		binary:           false,
		lowerNibble:      false,
	}
}

/*
func appendRune(slice *[]rune, r *rune) {
	// Capacity of the underlying array should have been setup not to cause
	// reallocation.
	// TODO: Add warning when slice capacity is about to be reached.
	*slice = append(*slice, *r)
}
*/
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

func (state *codecState) reset() {
	state.keyIndex = 0
	state.table = 0
	state.numberOfTables = len(CharacterTables)
	state.charCounter = 0
	state.gotChangeKeyChar = false
	state.keyChange = false
	state.shift = false
	state.binary = false
	state.lowerNibble = false
}

func (state *codecState) nextTable(output *[]rune) {
	state.table = (state.table + 1) % state.numberOfTables
	if output != nil {
		*output = append(*output, nextTableChar)
		state.charCounter++
	}
}

func (state *codecState) toggleCase(output *[]rune) error {
	if output != nil {
		err := state.gotoTable(secondaryTable, output)
		if err != nil {
			return err
		}
		*output = append(*output, caseToggleChar)
		state.charCounter++
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
		state.charCounter++
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

// changeKey adds the control character and key id necessary to change to
// another key. The character immediately following what this function writes
// must use the new key to encipher or decipher rest of the encoded text. When
// using the new key to cipher the first character, the state should have been
// reset to the initial state. NB! This function does not validate that Key is a
// valid key. Don't forget to state.reset() after calling this function.
func (state *codecState) changeKey(key *Key, output *[]rune) error {
	if output == nil || key == nil {
		return ErrNilPointer
	}
	err := state.gotoTable(secondaryTable, output)
	if err != nil {
		return err
	}
	*output = append(*output, changeKeyChar)
	state.charCounter++
	*output = append(*output, key.Id...)
	state.charCounter = state.charCounter + len(key.Id)
	return nil
}

// pad() adds numberOfCharacters of nextTableChar (Z) at the end of
// output rune slice. Function is used to extend an encoded text into an even
// amount of 5 character groups. Suggested calculation of numberOfCharacters:
// (t.instance.GroupSize - (lengthOfAllEncodedTexts % t.instance.GroupSize)) % t.instance.GroupSize
func (state *codecState) pad(numberOfCharacters int, output *[]rune) error {
	if output == nil {
		return ErrNilPointer
	}
	for i := 0; i < numberOfCharacters; i++ {
		*output = append(*output, nextTableChar)
		state.charCounter++
	}
	return nil
}

// encodeCharacter figures out which character sequence to write into the
// EncodedText field and adjust the state. When the first rune that can not be
// found in one of the tables appear, we switch to binary mode and will not exit
// this mode unless reaching the end or running out of key runes (where it will
// switch to the next key).
func (state *codecState) encodeCharacter(input *rune, output *[]rune) error {
	if state.binary {
		return errors.New("binary mode not implemented yet")
	}

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
				char := rune(i) + rune('A') // Column A-Z in the character table
				*output = append(*output, char)
				state.charCounter++
				char = 0
				break
			}
		}
		if foundIt {
			break
		}
	}
	// zero the copy of rune
	c = 0
	if !foundIt {
		// enter binary mode
		panic("binary mode not implemented yet")
	}

	return nil
}

// decodeCharacter decodes a rune and appends plain text to the output rune
// slice and/or sets the state for further processing by the calling function.
func (state *codecState) decodeCharacter(input *rune, output *[]rune) error {
	if *input < rune('A') || *input > rune('Z') {
		return ErrInvalidCoding
	}

	if state.binary {
		return errors.New("binary mode not implemented yet")
	}

	// If previous char was a the changeKeyChar (Y), current character is the
	// first of the new key to change to.
	if state.gotChangeKeyChar {
		state.gotChangeKeyChar = false
		state.keyChange = true
	}
	// Since decodeCharacter() does not know how long a key id is (the instance's
	// GroupSize), this state need to be reset from the calling function when the
	// key id has been harvested from the deciphered text.
	if state.keyChange {
		return nil
	}

	// input character is an index (column) in one of the tables (state.table).
	col := int(*input - rune('A'))
	if col >= len(CharacterTables[state.table]) {
		return ErrTableTooShort
	}

	char := CharacterTables[state.table][col]

	if char == specialOpChar {
		switch state.table {
		case primaryTable:
			// Only one control character in this table...
			switch *input {
			case nextTableChar:
				state.nextTable(nil)
			default:
				return ErrInvalidControlChar
			}
		case secondaryTable:
			// There are four control characters in this table...
			switch *input {
			case binaryToggleChar:
				state.toggleBinary(nil)
			case caseToggleChar:
				state.toggleCase(nil)
			case changeKeyChar:
				state.gotChangeKeyChar = true
			case nextTableChar:
				state.nextTable(nil)
			default:
				return ErrInvalidControlChar
			}
		default:
			return ErrUnsupportedTable
		}
	} else {
		if state.shift && char != spaceChar {
			toLower(&char, &char)
		}
		*output = append(*output, char)
		state.charCounter++
	}
	char = 0
	return nil
}

/* // Encode codes the PlainText field into the EncodedText field of a Message
// struct. Encode will prepend one star (*) in the beginning and add a key
// change if the message is more than Krypto431.KeyLength (minus characters
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
*/

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

// FindKey returns the first un-used key of the configured group size where all
// recipients are keepers of that key. If the recipient slice is empty, it will
// find the first un-used anonymous key (a key without any keepers). Function
// returns a pointer to the key. FindKey will not mark the key as used.
func (r *Krypto431) FindKey(recipients ...[]rune) *Key {
	numberOfRecipients := len(recipients)
	for i := range r.Keys {
		if r.Keys[i].Used {
			continue
		}
		if len(r.Keys[i].Id) != r.GroupSize {
			continue
		}
		if numberOfRecipients == 0 {
			// Find an anonymous key
			if len(r.Keys[i].Keepers) == 0 {
				// Found an anonymous key
				return &r.Keys[i]
			}
		} else {
			// Find a key where all recipients are keepers of that key.
			if AllNeedlesInHaystack(&recipients, &r.Keys[i].Keepers) {
				// Found a key where all recipients are keepers.
				return &r.Keys[i]
			}
		}
	}
	// If we reached here, we found no key.
	return nil
}

// GetKey() searches for a Key object with an Id of keyId and returns a pointer
// to this Key or error if not found.
func (r *Krypto431) GetKey(keyId []rune) (*Key, error) {
	k := strings.ToUpper(strings.TrimSpace(string(keyId)))
	for i := range r.Keys {
		if k == string(r.Keys[i].Id) {
			return &r.Keys[i], nil
		}
	}
	return nil, fmt.Errorf("key %s not found", k)
}

// MarkKeyUsed() looks for the keyId among the instance's Keys and sets the Used
// property to true or false depending on what the "used" variable is set to.
func (r *Krypto431) MarkKeyUsed(keyId []rune, used bool) error {
	k := strings.ToUpper(strings.TrimSpace(string(keyId)))
	for i := range r.Keys {
		if k == string(r.Keys[i].Id) {
			r.Keys[i].Used = used
			return nil
		}
	}
	return fmt.Errorf("key %s not found", k)
}

// EnrichWithKey finds the first appropriate key for this Message structure
// where each of the Messages Recipients are Keepers of the same key. If
// CipherText and KeyId already appear to be present, function will just return.
// If CipherText appear to be present, but message KeyId is empty it will return
// an error. If there is no CipherText or KeyId, the function will try to find
// one where all recipients are keepers of this key. The message KeyId will be
// used by diana.Trigraph during encryption/decryption.
func (m *Message) EnrichWithKey() error {
	if len(m.PlainText) == 0 {
		return errors.New("message plain text is empty")
	}
	if len(m.KeyId) > 0 {
		// already enriched with a KeyId, check if it's of correct length or used, if so, return error otherwise OK
		if len(m.KeyId) != m.instance.GroupSize {
			return fmt.Errorf("message key id is not %d letters long (configured group size)", m.instance.GroupSize)
		}
		for i := range m.instance.Keys {
			if EqualRunes(&m.instance.Keys[i].Id, &m.KeyId) {
				if m.instance.Keys[i].Used {
					return fmt.Errorf("message already enriched with used KeyId %s", string(m.KeyId))
				} else if m.instance.Keys[i].Compromised {
					return fmt.Errorf("message already enriched with compromised KeyId %s", string(m.KeyId))
				} else {
					return nil
				}
			}
		}
		return errors.New("message enriched with non-existing key, unable to encipher plain text")
	}
	if len(m.CipherText) > 0 {
		// message appear to have cipher text already, do not enrich with key and do
		// not validate if the key exists (decipher will fail if it doesn't exist
		// anyway).
		if len(m.KeyId) != m.instance.GroupSize {
			return errors.New("message already contain cipher text, but key ID is empty or not of correct length")
		}
		return nil
	}

	designatedKey := m.instance.FindKey(m.Recipients...)
	if designatedKey == nil {
		if len(m.Recipients) == 0 {
			return errors.New("did not find an anonymous key (a key without keepers)")
		} else {
			plural := "is keeper of the"
			if len(m.Recipients) > 1 {
				plural = "are keepers of the same"
			}
			return fmt.Errorf("did not find a valid key where %s %s key", JoinRunesToString(&m.Recipients, ", "), plural)
		}
	}
	// Mark key as used.
	designatedKey.Used = true
	// Enrich message instance with key id.
	m.KeyId = designatedKey.Id
	return nil
}

// Encipher() enciphers the PlainText field into the CipherText field of a
// Message object. Verbs encrypt and decrypt are only used for AES
// encryption/decryption of the persistance file, while words encipher and
// decipher are used for message ciphering in Krypto431.
func (m *Message) Encipher() error {
	err := m.EnrichWithKey()
	if err != nil {
		return fmt.Errorf("unable to enrich message with a key: %w", err)
	}
	Wipe(&m.CipherText)
	// TODO: The encode phase should really go into a new Encode() function.
	//
	// Encode plaintext...
	state := newState()
	// An encoded message contains one or more chunks. Each chunk is enciphered
	// with a key. The last chunk need to fill out with table changers (Z) so that
	// the sum of the length of all chunks are divided by GroupSize without a
	// remainder (mod % GroupSize).
	chunks := make([]chunk, 0, DefaultChunkCapacity)
	chunk := newChunk(m.instance.GroupSize)
	// First chunk obviously uses the message key id...
	keyPtr, err := m.instance.GetKey(m.KeyId)
	if err != nil {
		return err
	}
	chunk.key = keyPtr
	// If something fails, we need to release all keys we have used.
	releaseKeys := true
	defer func() {
		if releaseKeys {
			m.instance.MarkKeyUsed(m.KeyId, false)
			Wipe(&m.KeyId)
			chunk.key.Used = false
			for i := range chunks {
				chunks[i].key.Used = false
				chunks[i].Wipe()
			}
			chunk.Wipe()
		}
	}()
	for i := range m.PlainText {
		if state.charCounter >= chunk.key.KeyLength()-m.instance.GroupSize-ControlCharactersNeededToChangeKey {
			keyPtr := m.instance.FindKey(m.Recipients...)
			if keyPtr == nil {
				return ErrOutOfKeys
			}
			err := state.changeKey(keyPtr, &chunk.encodedText)
			if err != nil {
				return err
			}
			keyPtr.Used = true
			chunks = append(chunks, chunk)
			chunk = newChunk(m.instance.GroupSize)
			chunk.key = keyPtr
			state.reset()
		}
		err := state.encodeCharacter(&m.PlainText[i], &chunk.encodedText)
		if err != nil {
			return err
		}
	}
	// Count length of all chunks and make sure the last chunk compensates for
	// modulo GroupSize length of all EncodedTexts.
	// Last chunk is current chunk...
	lengthOfAllEncodedTexts := len(chunk.encodedText)
	for i := range chunks {
		lengthOfAllEncodedTexts += len(chunks[i].encodedText)
	}
	err = state.pad((m.instance.GroupSize-(lengthOfAllEncodedTexts%m.instance.GroupSize))%m.instance.GroupSize, &chunk.encodedText)
	if err != nil {
		return err
	}
	// Finally, add the current chunk to the slice...
	chunks = append(chunks, chunk)
	//
	// Encipher each encodedText with each chunk's key...
	//
	for i := range chunks {
		if chunks[i].key == nil {
			return ErrNilPointer
		}
		if len(chunks[i].encodedText) > chunks[i].key.KeyLength() {
			tooShortKeyMsg := "key %s is too short to encipher chunk %d "
			if len(chunks) > 1 {
				tooShortKeyMsg += "out of %d chunks"
			} else {
				tooShortKeyMsg += "(message is only %d chunk)"
			}
			return fmt.Errorf(tooShortKeyMsg, string(chunks[i].key.Id), i+1, len(chunks))
		}
		for ki := range chunks[i].encodedText {
			var output rune
			err := diana.TrigraphRune(&output, &chunks[i].key.Runes[ki], &chunks[i].encodedText[ki])
			if err != nil {
				return err
			}
			m.CipherText = append(m.CipherText, output)
		}
	}
	// DEBUG: remove print-outs below...
	for i := range chunks {
		grouped, err := groups(&chunks[i].encodedText, m.instance.GroupSize, 0)
		if err != nil {
			return err
		}
		fmt.Printf("key: %s, enctxt: %s"+LineBreak, string(chunks[i].key.Id), string(*grouped))
	}
	grouped, err := groups(&m.CipherText, m.instance.GroupSize, 0)
	if err != nil {
		return err
	}
	fmt.Printf("        ciphertext: %s"+LineBreak, string(*grouped))

	releaseKeys = false
	return nil
}

// Decipher deciphers the CipherText field into the PlainText field of a Message
// object. PlainText will be replaced with deciphered text if text already
// exists. Decipher does not use a separate decoding function as simultaneous
// decoding is needed to support CipherText enciphered with multiple keys. If
// deciphering succeeds, all keys used in the message will be marked `used`.
func (m *Message) Decipher() error {
	if len(m.KeyId) != m.instance.GroupSize {
		return ErrNoKey
	}
	if len(m.CipherText) < m.instance.GroupSize {
		return ErrCipherTextTooShort
	}
	keyPtr, err := m.instance.GetKey(m.KeyId)
	if err != nil {
		return err
	}
	keyStack := make([]*Key, 0, DefaultChunkCapacity)
	keyStack = append(keyStack, keyPtr)
	markKeysUsed := false
	defer func() {
		if markKeysUsed {
			for i := range keyStack {
				keyStack[i].Used = true
			}
		}
	}()
	if keyPtr.Used {
		fmt.Fprintf(os.Stderr, "Warning: key %s marked as already used!"+LineBreak, keyPtr.IdString())
	}
	Wipe(&m.PlainText)
	keyIndexCounter := 0
	nextKey := make([]rune, 0, m.instance.GroupSize)
	state := newState()
	for i := range m.CipherText {
		var encodedChar rune
		if keyIndexCounter >= len(keyPtr.Runes) {
			//fmt.Fprintf(os.Stderr, "%d (keylen=%d)\n", keyIndexCounter, len(keyPtr.Runes))
			return fmt.Errorf("out-of-key error, %s is too short", string(keyPtr.Id))
		}
		err := diana.TrigraphRune(&encodedChar, &keyPtr.Runes[keyIndexCounter], &m.CipherText[i])
		if err != nil {
			return err
		}
		keyIndexCounter++
		err = state.decodeCharacter(&encodedChar, &m.PlainText)
		if err != nil {
			return err
		}
		if state.keyChange {
			nextKey = append(nextKey, encodedChar)
			if len(nextKey) >= m.instance.GroupSize {
				var err error
				keyPtr, err = m.instance.GetKey(nextKey)
				if err != nil {
					return err
				}
				keyStack = append(keyStack, keyPtr)
				keyIndexCounter = 0
				Wipe(&nextKey)
				state.reset()
			}
		}
	}
	fmt.Println(string(m.PlainText))
	markKeysUsed = true
	return nil
}

// TryDecipherPlainText attempts to identify PlainText that is actually
// CipherText prepended with a key. If optional dryrun is not true, function
// will copy possible key ID and ciphertext to the message and attempt to
// decipher it. On failure to decipher, the message object (KeyId and PlainText)
// is restored. Function will not run if the message has the KeyId filled in or
// the first group of the PlainText (key ID) can not be found in the key store.
// Returns error if CipherText detection/decipher was unsuccessful, nil if
// successful.
func (m *Message) TryDecipherPlainText(dryrun ...bool) error {
	if len(m.KeyId) > 0 {
		return ErrNotCipherText
	}
	filteredText := make([]rune, 0, len(m.PlainText))
	defer Wipe(&filteredText)
	for i := range m.PlainText {
		switch {
		case unicode.IsSpace(m.PlainText[i]), m.PlainText[i] == '=':
			continue
		}
		c := unicode.ToUpper(m.PlainText[i])
		if !(c >= 'A' && c <= 'Z') {
			return ErrNotCipherText
		}
		filteredText = append(filteredText, c)
	}
	if len(filteredText) < m.instance.GroupSize*2 {
		return ErrNotCipherText
	}
	key, err := m.instance.GetKey(filteredText[:m.instance.GroupSize])
	if err != nil {
		return fmt.Errorf("%v: %w", ErrNotCipherText, err)
	}
	// If optional dryrun == true, we are satisfied...
	if len(dryrun) > 0 {
		if dryrun[0] {
			return nil
		}
	}
	// First group in plaintext seem to be a key we have, try deciphering it...
	restore := true
	oldPlainText := RuneCopy(&m.PlainText)
	oldCipherText := RuneCopy(&m.CipherText)
	defer func() {
		if restore {
			Wipe(&m.KeyId)
			m.PlainText = RuneCopy(&oldPlainText)
			m.CipherText = RuneCopy(&oldCipherText)
		}
		Wipe(&oldPlainText)
		Wipe(&oldCipherText)
	}()
	m.KeyId = RuneCopy(&key.Id)
	cipherText := filteredText[m.instance.GroupSize:]
	m.CipherText = RuneCopy(&cipherText)
	err = m.Decipher()
	if err != nil {
		return fmt.Errorf("%v: %w", ErrNotCipherText, err)
	}
	restore = false
	return nil
}
