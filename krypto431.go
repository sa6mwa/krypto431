package krypto431

import (
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"math"
	"strings"
	"sync"

	"github.com/sa6mwa/dtg"
	"github.com/sa6mwa/krypto431/crand"
)

// defaults, most are exported
const (
	useCrandWipe               bool   = true
	DefaultGroupSize           int    = 5
	DefaultKeyLength           int    = 350 // 70 groups, 5 groups per row is 14 rows total
	DefaultColumns             int    = 110
	DefaultKeyColumns          int    = 30
	DefaultSaveFile            string = "~/.krypto431.gob"
	DefaultKeyCapacity         int    = 50000                                   // 50k keys
	DefaultChunkCapacity       int    = 20                                      // 20 chunks
	DefaultEncodedTextCapacity int    = DefaultKeyLength * 2                    // 700
	DefaultMessageCapacity     int    = 10000                                   // 10k messages
	DefaultPlainTextCapacity   int    = DefaultKeyLength * DefaultChunkCapacity // 7000
	MinimumSupportedKeyLength  int    = 20
	MinimumColumnWidth         int    = 85 // Trigraph table is 80 characters wide
	MinimumSaltLength          int    = 32
	MinimumPasswordLength      int    = 8
	// Fixed salt for pbkdf2 derived keys. Can be changed using
	// krypto431.New(krypto431.WithSalt(atLeast32characterSaltString)) when
	// initiating a new instance.
	DefaultSalt string = "418F04528EF6876541AF850858CD1CF394E96956607103B356DD74ADB6948001"
)

var (
	ErrNilPointer         = errors.New("received a nil pointer")
	ErrNoCipherText       = errors.New("message cipher text is too short to decipher")
	ErrNoKey              = errors.New("message has an invalid or no key")
	ErrKeyNotFound        = errors.New("key not found")
	ErrInvalidCoding      = errors.New("invalid character in encoded text (must be between A-Z)")
	ErrInvalidControlChar = errors.New("invalid control character")
	ErrTableTooShort      = errors.New("out-of-bounds, character table is too short")
	ErrUnsupportedTable   = errors.New("character table not supported")
	ErrOutOfKeys          = errors.New("can not encipher multi-key message, unable to find additional key(s)")
	ErrNoCallSign         = errors.New("need to specify your call-sign")
	ErrNoSaveFile         = errors.New("missing file name for persisting keys, messages and settings")
	ErrInvalidGroupSize   = errors.New("group size must be 1 or longer")
	ErrKeyTooShort        = fmt.Errorf("key length must be %d characters or longer", MinimumSupportedKeyLength)
	ErrTooNarrow          = fmt.Errorf("column width must be at least %d characters wide", MinimumColumnWidth)
	ErrKeyColumnsTooShort = errors.New("key column width less than group size")
)

// Wiper interface (for Keys and Messages only). Not used internally in package.
type Wiper interface {
	Wipe() error
	RandomWipe() error
	ZeroWipe() error
}

// Returns a grouped string according to GroupSize set in the instance
// (Krypto431). Keys and Messages implement this interface.
type GroupFormatter interface {
	Groups() (*[]rune, error)
	GroupsBlock() (*[]rune, error)
}

// Krypto431 store generated keys, plaintext, ciphertext, callsign(s) and
// configuration items. It is mandatory to populate MyCallSigns with at least
// one call sign (something identifying yourself in message handling). It will
// be converted to upper case. Mutex and persistance file (saveFile) are not
// exported meaning values will not be persisted to disk.
type Krypto431 struct {
	mx                        *sync.Mutex
	saveFile                  string
	saveFileKey               *[]byte
	salt                      *[]byte
	overwriteSaveFileIfExists bool
	interactive               bool
	GroupSize                 int       `json:",omitempty"`
	KeyLength                 int       `json:",omitempty"`
	Columns                   int       `json:",omitempty"`
	KeyColumns                int       `json:",omitempty"`
	Keys                      []Key     `json:",omitempty"`
	Messages                  []Message `json:",omitempty"`
	MyCallSigns               [][]rune  `json:",omitempty"`
}

// Key struct holds a key. Keepers is a list of callsigns or other identifiers
// that have access to this key (and can use it for encryption/decryption). The
// proper procedure is to share the key with it's respective keeper(s). By
// default, all your callsigns (MyCallSigns) will be appended to the Keepers
// slice.
type Key struct {
	Id       []rune   `json:",omitempty"`
	Runes    []rune   `json:",omitempty"`
	Keepers  [][]rune `json:",omitempty"`
	Expires  dtg.DTG
	Created  dtg.DTG
	Used     bool `json:",omitempty"`
	instance *Krypto431
}

// Message holds plaintext and ciphertext. To encrypt, you need to populate the
// PlainText (OR Binary) and Recipients fields, the rest will be updated by the
// Encrypt function which will choose the next available key. If PlainText is
// longer than the key, the Encrypt function will use another key where the
// key's Keepers field matches all of the Recipients. If there are not enough
// keys to encrypt the message, Encrypt will fail. Encrypt will cache all
// non-used keys from the database matching the Recipients into the instance
// Keys slice before enciphering. To decrypt you need to have ciphertext in the
// CipherText field and the start KeyId. All binary data in the message will be
// appended to the Binary field. There is no method (yet) to figure out which of
// your keys can be used to decipher the message. If the KeyId is not already in
// your instace's Keys slice it will be fetched from the database or fail. The
// KeyId should be the first group in your received message.
type Message struct {
	DTG        dtg.DTG
	GroupCount int      `json:",omitempty"`
	KeyId      []rune   `json:",omitempty"`
	PlainText  []rune   `json:",omitempty"`
	Binary     []byte   `json:",omitempty"`
	CipherText []rune   `json:",omitempty"`
	Recipients [][]rune `json:",omitempty"`
	instance   *Krypto431
}

// A chunk is internal to the Encipher function and is either the complete
// PlainText encoded or - if the message is too long for the key - part of the
// PlainText where all but the last chunk ends in a key change. Each chunk is to
// be enciphered with a key allowing to chain multiple keys for longer messages.
type chunk struct {
	encodedText []rune
	key         *Key
}

// Returns an initialized chunk (groupSize is usually msg.instance.GroupSize).
func newChunk(groupSize int) chunk {
	return chunk{
		encodedText: make([]rune, 0, DefaultEncodedTextCapacity),
		key:         nil,
	}
}

// Wipe wipes a rune slice.
func Wipe(b *[]rune) error {
	if b == nil {
		return ErrNilPointer
	}
	if useCrandWipe {
		err := RandomWipe(b)
		if err != nil {
			return err
		}
	} else {
		err := ZeroWipe(b)
		if err != nil {
			return err
		}
	}
	return nil
}

// RandomWipe wipes a rune slice with random runes.
func RandomWipe(b *[]rune) error {
	if b == nil {
		return ErrNilPointer
	}
	written, err := crand.ReadRunes(*b)
	if err != nil || written != len(*b) {
		if err != nil {
			return err
		}
		ZeroWipe(b)
	}
	*b = nil
	return nil
}

// ZeroWipe wipes a rune slice with zeroes.
func ZeroWipe(b *[]rune) error {
	if b == nil {
		return ErrNilPointer
	}
	for i := range *b {
		(*b)[i] = 0
	}
	*b = nil
	return nil
}

// WipeBytes wipes a byte slice.
func WipeBytes(b *[]byte) error {
	if b == nil {
		return ErrNilPointer
	}
	if useCrandWipe {
		err := RandomWipeBytes(b)
		if err != nil {
			return err
		}
	} else {
		err := ZeroWipeBytes(b)
		if err != nil {
			return err
		}
	}
	return nil
}

// RandomWipeBytes wipes a byte slice with random bytes.
func RandomWipeBytes(b *[]byte) error {
	if b == nil {
		return ErrNilPointer
	}
	written, err := crand.Read(*b)
	if err != nil || written != len(*b) {
		if err != nil {
			return err
		}
		ZeroWipeBytes(b)
	}
	*b = nil
	return nil
}

// ZeroWipeBytes wipes a byte slice with zeroes.
func ZeroWipeBytes(b *[]byte) error {
	if b == nil {
		return ErrNilPointer
	}
	for i := range *b {
		(*b)[i] = 0
	}
	*b = nil
	return nil
}

// Wipe overwrites key with either random runes or zeroes.
func (k *Key) Wipe() error {
	if useCrandWipe {
		err := k.RandomWipe()
		if err != nil {
			return err
		}
	} else {
		err := k.ZeroWipe()
		if err != nil {
			return err
		}
	}
	return nil
}

// RandomWipe overwrites key with random runes.
func (k *Key) RandomWipe() error {
	runeSlices := []*[]rune{&k.Runes, &k.Id}
	for i := range runeSlices {
		written, err := crand.ReadRunes(*runeSlices[i])
		if err != nil || written != len(*runeSlices[i]) {
			if err != nil {
				log.Println(err.Error())
			}
			log.Printf("ERROR, wrote %d runes, but expected to write %d", written, len(*runeSlices[i]))
			// zero-wipe rune slice instead...
			for y := 0; y < len(*runeSlices[i]); y++ {
				(*runeSlices[i])[y] = 0
			}
		}
		*runeSlices[i] = nil
	}
	return nil
}

// ZeroWipe zeroes a key.
func (k *Key) ZeroWipe() error {
	for i := 0; i < len(k.Runes); i++ {
		k.Runes[i] = 0
	}
	k.Runes = nil
	for i := 0; i < len(k.Id); i++ {
		k.Id[i] = 0
	}
	k.Id = nil
	return nil
}

// KeyLength() returns the length of this key instance.
func (k *Key) KeyLength() int {
	return len(k.Runes)
}

// Returns a rune slice where each group is separated by a space. If columns is
// above 0 the function will insert a line break instead of a space before
// extending beyond that column length. Don't forget to Wipe(myRuneSlice) when
// you are done!
func groups(input *[]rune, groupsize int, columns int) (*[]rune, error) {
	if input == nil {
		return nil, ErrNilPointer
	}
	if groupsize <= 0 {
		return nil, errors.New("groupsize must be above 0")
	}
	output := make([]rune, 0, int(math.Ceil(float64(len(*input))/float64(groupsize)))*(groupsize+1))
	runeCount := 0
	outCount := 0
	for i := 0; i < len(*input); i++ {
		output = append(output, (*input)[i])
		outCount++
		runeCount++
		if runeCount == groupsize {
			if i != len(*input)-1 {
				if columns > 0 && outCount >= columns-groupsize-1 {
					output = append(output, []rune(LineBreak)...)
					outCount = 0
				} else {
					output = append(output, rune(' '))
					outCount++
				}
			}
			runeCount = 0
		}
	}
	return &output, nil
}

// Groups for keys return a rune slice where each number of GroupSize runes are
// separated by a space. Don't forget to Wipe() this slice when you are done!
func (k *Key) Groups() (*[]rune, error) {
	return groups(&k.Runes, k.instance.GroupSize, 0)
}

// Groups for messages return a rune slice where each group (GroupSize) is
// separated by space. Don't forget to Wipe() this slice when you are done!
func (t *Message) Groups() (*[]rune, error) {
	// There is no need to group the Message (non-encoded) field.
	return groups(&t.CipherText, t.instance.GroupSize, 0)
}

// GroupsBlock returns a string representation of the key where each group is
// separated by a space and new lines if the block is longer than
// Krypto431.Columns (or defaultColumns). Don't forget to Wipe(b []rune) this
// slice when you are done!
func (k *Key) GroupsBlock() (*[]rune, error) {
	return groups(&k.Runes, k.instance.GroupSize, k.instance.KeyColumns)
}

// GroupsBlock for Message
func (t *Message) GroupsBlock() (*[]rune, error) {
	return groups(&t.CipherText, t.instance.GroupSize, t.instance.Columns)
}

// Wipe overwrites key, plaintext and ciphertext with random runes or zeroes.
// The order is highest priority first (plaintext), then ciphertext and finally
// the groupcount and keyid. Nilling the rune slices should promote it for
// garbage collection.
func (t *Message) Wipe() {
	if useCrandWipe {
		t.RandomWipe()
	} else {
		t.ZeroWipe()
	}
}

// RandomWipe assigned method for Text wipes PlainText, CipherText, GroupCount
// and KeyId fields.
func (t *Message) RandomWipe() {
	// wipe PlainText
	written, err := crand.ReadRunes(t.PlainText)
	if err != nil || written != len(t.PlainText) {
		for i := 0; i < len(t.PlainText); i++ {
			t.PlainText[i] = 0
		}
	}
	t.PlainText = nil
	// wipe CipherText
	written, err = crand.ReadRunes(t.CipherText)
	if err != nil || written != len(t.CipherText) {
		for i := 0; i < len(t.CipherText); i++ {
			t.CipherText[i] = 0
		}
	}
	t.CipherText = nil
	// wipe GroupCount
	t.GroupCount = crand.Int()
	// wipe KeyId
	written, err = crand.ReadRunes(t.KeyId)
	if err != nil || written != len(t.KeyId) {
		for i := 0; i < len(t.KeyId); i++ {
			t.KeyId[i] = 0
		}
	}
	t.KeyId = nil
	/* 	// wipe Chunks
	   	for x := range t.EncodedChunks {
	   		t.EncodedChunks[x].RandomWipe()
	   	}
	*/
}

// ZeroWipe assigned method for PlainText writes zeroes to Text and EncodedText
// fields.
func (t *Message) ZeroWipe() {
	// wipe PlainText
	for i := 0; i < len(t.PlainText); i++ {
		t.PlainText[i] = 0
	}
	t.PlainText = nil
	// wipe CipherText
	for i := 0; i < len(t.CipherText); i++ {
		t.CipherText[i] = 0
	}
	t.CipherText = nil
	// wipe GroupCount
	t.GroupCount = 0
	// wipe KeyId
	for i := 0; i < len(t.KeyId); i++ {
		t.KeyId[i] = 0
	}
	t.KeyId = nil
	/* 	// wipe Chunks
	   	for x := range t.EncodedChunks {
	   		t.EncodedChunks[x].ZeroWipe()
	   	}
	*/
}

// Wipe overwrites a chunk with either random runes or zeroes.
func (c *chunk) Wipe() error {
	if useCrandWipe {
		err := c.RandomWipe()
		if err != nil {
			return err
		}
	} else {
		err := c.ZeroWipe()
		if err != nil {
			return err
		}
	}
	return nil
}

// Chunk RandomWipe overwrites chunk with random runes.
func (c *chunk) RandomWipe() error {
	c.key = nil
	runeSlices := []*[]rune{&c.encodedText}
	for i := range runeSlices {
		written, err := crand.ReadRunes(*runeSlices[i])
		if err != nil || written != len(*runeSlices[i]) {
			if err != nil {
				log.Println(err.Error())
			}
			log.Printf("ERROR, wrote %d runes, but expected to write %d", written, len(*runeSlices[i]))
			// zero-wipe rune slice instead...
			for y := 0; y < len(*runeSlices[i]); y++ {
				(*runeSlices[i])[y] = 0
			}
		}
		*runeSlices[i] = nil
	}
	return nil
}

// Chunk ZeroWipe zeroes a chunk
func (c *chunk) ZeroWipe() error {
	for i := 0; i < len(c.encodedText); i++ {
		c.encodedText[i] = 0
	}
	c.encodedText = nil
	c.key = nil
	return nil
}

// New creates a new Krypto431 instance.
func New(opts ...Option) Krypto431 {
	instance := Krypto431{
		saveFile:                  DefaultSaveFile,
		saveFileKey:               nil,
		overwriteSaveFileIfExists: false,
		interactive:               false,
		GroupSize:                 DefaultGroupSize,
		KeyLength:                 DefaultKeyLength,
		Columns:                   DefaultColumns,
		KeyColumns:                DefaultKeyColumns,
		Keys:                      make([]Key, 0, DefaultKeyCapacity),
		Messages:                  make([]Message, 0, DefaultMessageCapacity),
	}
	salt, err := hex.DecodeString(DefaultSalt)
	if err != nil {
		salt = nil
	} else {
		instance.salt = &salt
	}
	for _, opt := range opts {
		opt(&instance)
	}
	if instance.mx == nil {
		instance.mx = &sync.Mutex{}
	}
	return instance
}

// Option fn type for the New() construct.
type Option func(r *Krypto431)

// WithKey overrides deriving the encryption key for the save file from a
// password by using the key directly. Must be 32 bytes long.
func WithKey(key *[]byte) Option {
	if key == nil || len(*key) != 32 {
		return func(k *Krypto431) {
			k.saveFileKey = nil
		}
	}
	return func(k *Krypto431) {
		k.saveFileKey = key
	}
}

// WithSalt() runs the salt string through hex.DecodeString() to derive a byte
// slice that, if at least 32 bytes long, is used instead of the default
// internal fixed salt.
func WithSalt(salt string) Option {
	bsalt, err := hex.DecodeString(salt)
	if err != nil || len(bsalt) < MinimumSaltLength {
		// KDF function uses SHA256 so the salt should be at least 32 bytes (20
		// bytes if it were SHA1).
		return func(r *Krypto431) {
			r.salt = nil
		}
	}
	return func(r *Krypto431) {
		r.salt = &bsalt
	}
}
func WithCallSign(cs string) Option {
	return func(r *Krypto431) {
		r.MyCallSigns = append(r.MyCallSigns, []rune(cs))
	}
}
func WithCallSigns(css ...string) Option {
	return func(r *Krypto431) {
		for i := range css {
			r.MyCallSigns = append(r.MyCallSigns, []rune(css[i]))
		}
	}
}
func WithMutex(mu *sync.Mutex) Option {
	return func(r *Krypto431) {
		r.mx = mu
	}
}
func WithGroupSize(n int) Option {
	return func(r *Krypto431) {
		r.GroupSize = n
	}
}
func WithKeyLength(n int) Option {
	return func(r *Krypto431) {
		r.KeyLength = n
	}
}
func WithColumns(n int) Option {
	return func(r *Krypto431) {
		r.Columns = n
	}
}
func WithKeyColumns(n int) Option {
	return func(r *Krypto431) {
		r.KeyColumns = n
	}
}
func WithSaveFile(savefile string) Option {
	return func(r *Krypto431) {
		r.saveFile = savefile
	}
}
func WithOverwriteSaveFileIfExists(b bool) Option {
	return func(r *Krypto431) {
		r.overwriteSaveFileIfExists = b
	}
}
func WithInteractive(b bool) Option {
	return func(r *Krypto431) {
		r.interactive = b
	}
}

// AllNeedlesInHaystack returns true is all needles can be found in the
// haystack, but if one slice in the haystack is a star (*) it will always
// return true. Intended to find Keepers of Keys where needles are
// Message.Recipients and haystack is Key.Keepers.
func AllNeedlesInHaystack(needles *[][]rune, haystack *[][]rune) bool {
	if needles == nil || haystack == nil {
		return false
	}
	if len(*needles) == 0 || len(*haystack) == 0 {
		return false
	}
loop:
	for i := range *needles {
		for x := range *haystack {
			if string((*haystack)[x]) == `*` {
				return true
			}
			if string((*haystack)[x]) == string((*needles)[i]) {
				continue loop
			}
		}
		return false
	}
	return true
}

// Methods assigned to the main struct...

// Asserts that settings in the instance are valid. Function is intended to be
// executed after New() to assert that settings are valid.
func (k *Krypto431) Assert() error {
	if len(k.saveFile) == 0 {
		return ErrNoSaveFile
	}
	if k.GroupSize < 1 {
		return ErrInvalidGroupSize
	}
	if k.KeyLength < MinimumSupportedKeyLength {
		return ErrKeyTooShort
	}
	if k.Columns < MinimumColumnWidth {
		return ErrTooNarrow
	}
	if k.KeyColumns < k.GroupSize {
		return ErrKeyColumnsTooShort
	}
	return nil
}

// Close is an alias for Krypto431.Wipe()
func (k *Krypto431) Close() {
	k.Wipe()
}

// Wipe instance assigned method wipes all in-memory keys and texts (plaintext
// and ciphertext) with random runes or zeroes in an attempt to keep sensitive
// information for as short time as possible in memory. Whenever keys or
// ciphertexts are written to the database they are wiped automatically,
// respectively, but it is up to the user of the API to call Wipe() or Close()
// when using the methods to read keys and ciphertext from database, file or
// stdin when done processing them.
func (k *Krypto431) Wipe() {
	for i := range k.Keys {
		k.Keys[i].Wipe()
	}
	k.Keys = nil
	for i := range k.Messages {
		k.Messages[i].Wipe()
	}
	k.Messages = nil
	// wipe saveFileKey
	WipeBytes(k.saveFileKey)
	// wipe salt
	WipeBytes(k.salt)
}

// NewTextMessage() is a variadic function where first argument is the message,
// second is a comma-separated list with recipients, third a key id to override
// the key finder function and use a specific key (not marked "used"). First
// argument is mandatory, rest are optional.
func (k *Krypto431) NewTextMessage(msg ...string) (err error) {
	// 1st arg = message as a utf8 string (mandatory)
	// 2nd arg = recipients as a comma-separated list (optional)
	// 3rd arg = key id, overrides the key finder function (optional)

	if len(msg) == 0 {
		return errors.New("must at least provide the message text (first argument)")
	}

	message := Message{
		PlainText: []rune(strings.TrimSpace(msg[0])),
		instance:  k,
	}

	if len(message.PlainText) < 1 {
		return errors.New("message is empty")
	}

	if len(msg) >= 2 {
		recipients := strings.Split(msg[1], ",")
		for i := range recipients {
			message.Recipients = append(message.Recipients, []rune(strings.TrimSpace(strings.ToUpper(recipients[i]))))
		}
	}

	if len(msg) >= 3 {
		message.KeyId = []rune(strings.ToUpper(strings.TrimSpace(msg[2])))
		if len(message.KeyId) != k.GroupSize {
			return fmt.Errorf("key id \"%s\" must be %d characters long (the configured group size)", string(message.KeyId), k.GroupSize)
		}
	}

	/* EnrichWithKey() need to be changed:
	no err when key already present, and marked not used
	no err when ciphertext is already present, just return
	if there are no Recipients, find key that also has no Keepers (empty Keepers) / or my CS by default?
	*/

	err = message.Encipher()
	if err != nil {
		return err
	}
	k.Messages = append(k.Messages, message)
	return nil
}

// TODO: Implement! :)

//func (r *Krypto431) NewBinaryMessage()

//func (r *Krypto431) Encode(plaintext string) {}
//func (r *Krypto431) Decode(plaintext string) {}

// Generic function to convert an array of rune slices (runes) into a string
// slice.
func RunesToStrings(runes *[][]rune) (stringSlice []string) {
	for i := range *runes {
		stringSlice = append(stringSlice, string((*runes)[i]))
	}
	return
}

// Generic function to vet one or more keeper strings, comma-separated or not.
func VettedKeepers(keepers ...string) (vettedKeepers [][]rune) {
	for i := range keepers {
		subKeepers := strings.Split(keepers[i], ",")
		for a := range subKeepers {
			vettedKeeper := []rune(strings.ToUpper(strings.TrimSpace(subKeepers[a])))
			if len(vettedKeeper) > 0 {
				vettedKeepers = append(vettedKeepers, vettedKeeper)
			}
		}
	}
	return
}

// Function to compare two rune slices. Returns true if they are equal, false if
// not.
func EqualRunes(a *[]rune, b *[]rune) bool {
	if a == nil && b == nil {
		return true
	}
	if a == nil || b == nil {
		return false
	}
	if len(*a) != len(*b) {
		return false
	}
	for x := range *a {
		if (*a)[x] != (*b)[x] {
			return false
		}
	}
	return true
}
