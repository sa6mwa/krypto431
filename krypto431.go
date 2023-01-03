package krypto431

import (
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"os"
	"strings"
	"sync"

	"github.com/sa6mwa/dtg"
	"github.com/sa6mwa/krypto431/crand"
)

// defaults, most are exported
const (
	useCrandWipe               bool   = true
	MinimumCallSignLength      int    = 2
	DefaultGroupSize           int    = 5
	DefaultKeyLength           int    = 350 // 70 groups, 5 groups per row is 14 rows total
	DefaultColumns             int    = 110
	DefaultKeyColumns          int    = 30
	DefaultPersistence         string = "~/.krypto431.gob"
	DefaultKeyCapacity         int    = 50000                                   // 50k keys
	DefaultChunkCapacity       int    = 20                                      // 20 chunks
	DefaultEncodedTextCapacity int    = DefaultKeyLength * 2                    // 700
	DefaultMessageCapacity     int    = 10000                                   // 10k messages
	DefaultPlainTextCapacity   int    = DefaultKeyLength * DefaultChunkCapacity // 7000
	DefaultPBKDF2Iteration     int    = 310000                                  // https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html
	MinimumSupportedKeyLength  int    = 20
	MinimumColumnWidth         int    = 85 // Trigraph table is 80 characters wide
	MinimumSaltLength          int    = 32
	MinimumPasswordLength      int    = 8
	// Fixed salt for pbkdf2 derived keys. Can be changed using
	// krypto431.New(krypto431.WithSalt(hexEncodedSaltString)) when initiating a
	// new instance. You can use GenerateSalt() to generate a new salt for use in
	// WithSalt() and your UI program.
	DefaultSalt string = "d14461856f830fc5a1f9ba1b845fae5f61c54767ded39cf943174e6869b44476"
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
	ErrInvalidCallSign    = fmt.Errorf("invalid call-sign, should be at least %d characters long", MinimumCallSignLength)
	ErrNoPersistence      = errors.New("missing file name for persisting keys, messages and settings")
	ErrInvalidGroupSize   = errors.New("group size must be 1 or longer")
	ErrKeyTooShort        = fmt.Errorf("key length must be %d characters or longer", MinimumSupportedKeyLength)
	ErrTooNarrow          = fmt.Errorf("column width must be at least %d characters wide", MinimumColumnWidth)
	ErrKeyColumnsTooShort = errors.New("key column width less than group size")
	ErrFormatting         = errors.New("formatting error")
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
// configuration items. CallSign is mandatory (something identifying yourself in
// message handling). It will be converted to upper case. Mutex and persistance
// file (persistence) are not exported meaning values will not be persisted to
// disk.
type Krypto431 struct {
	mx                           *sync.Mutex
	persistence                  string
	persistenceKey               *[]byte
	salt                         *[]byte
	overwritePersistenceIfExists bool
	interactive                  bool
	GroupSize                    int
	KeyLength                    int
	Columns                      int
	KeyColumns                   int
	Keys                         []Key
	Messages                     []Message
	CallSign                     []rune
}

// Key struct holds a key. Keepers is a list of call-signs or other identifiers
// that have access to this key (and can use it for encryption/decryption). The
// proper procedure is to share the key with it's respective keeper(s).
type Key struct {
	Id          []rune
	Runes       []rune
	Keepers     [][]rune
	Created     dtg.DTG
	Expires     dtg.DTG
	Used        bool
	Compromised bool
	Comment     []rune
	instance    *Krypto431
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
	Recipients [][]rune
	From       []rune
	DTG        dtg.DTG
	GroupCount int
	KeyId      []rune
	PlainText  []rune
	Binary     []byte
	CipherText []rune
	Radiogram  []rune // Raw radiogram
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
	runeSlices := []*[]rune{&k.Runes, &k.Comment, &k.Id}
	for i := range k.Keepers {
		runeSlices = append(runeSlices, &k.Keepers[i])
	}
	for i := range runeSlices {
		written, err := crand.ReadRunes(*runeSlices[i])
		if err != nil || written != len(*runeSlices[i]) {
			if err != nil {
				fmt.Fprintln(os.Stderr, err.Error())
			}
			if written != len(*runeSlices[i]) {
				fmt.Fprintf(os.Stderr, "ERROR, wrote %d runes, but expected to write %d", written, len(*runeSlices[i]))
			}
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
	for x := range k.Keepers {
		for i := 0; i < len(k.Keepers[x]); i++ {
			k.Keepers[x][i] = 0
		}
		k.Keepers[x] = nil
	}
	k.Keepers = nil
	for i := 0; i < len(k.Comment); i++ {
		k.Comment[i] = 0
	}
	k.Comment = nil
	for i := 0; i < len(k.Id); i++ {
		k.Id[i] = 0
	}
	k.Id = nil
	return nil
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
		persistence:                  DefaultPersistence,
		persistenceKey:               nil,
		salt:                         nil,
		overwritePersistenceIfExists: false,
		interactive:                  false,
		GroupSize:                    DefaultGroupSize,
		KeyLength:                    DefaultKeyLength,
		Columns:                      DefaultColumns,
		KeyColumns:                   DefaultKeyColumns,
		Keys:                         make([]Key, 0, DefaultKeyCapacity),
		Messages:                     make([]Message, 0, DefaultMessageCapacity),
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
type Option func(k *Krypto431)

// WithKey overrides deriving the encryption key for the persistance-file from a
// password by using the key directly. Must be 32 bytes long. Beware! Underlying
// byte slice will be wiped when closing or wiping the Krypto431 instance, but
// the New() function returns a reference not a pointer meaning there could
// still be a copy of this key in memory after wiping.
func WithKey(key *[]byte) Option {
	if key == nil || len(*key) != 32 {
		return func(k *Krypto431) {
			k.persistenceKey = nil
		}
	}
	return func(k *Krypto431) {
		k.persistenceKey = key
	}
}

// As WithKey, but takes a string and attempts to hex decode it into a byte
// slice. Not recommended to use as it doesn't fail on error just nils the key
// and leaves memory traces that can not be wiped. Use SetKeyFromString() on the
// instance after New() instead.
func WithKeyString(hexEncodedString string) Option {
	nilKeyFunc := func(k *Krypto431) {
		k.persistenceKey = nil
	}
	if len(hexEncodedString) != 32*2 {
		return nilKeyFunc
	}
	key, err := hex.DecodeString(hexEncodedString)
	if err != nil {
		return nilKeyFunc
	}
	return func(k *Krypto431) {
		k.persistenceKey = &key
	}
}

// WithSalt() can be used to override the default fixed salt with a custom salt.
// Beware that the underlying byte slice will be wiped when closing or wiping
// the Krypto431 instance. Use hex.DecodeString() to generate a 32 byte slice
// from a 64 byte hex string produced by for example GenerateSalt().
func WithSalt(salt *[]byte) Option {
	// KDF function uses SHA256 so the salt should preferably be at least 32 bytes.
	if salt == nil || len(*salt) < 32 {
		return func(k *Krypto431) {
			k.salt = nil
		}
	}
	return func(k *Krypto431) {
		k.salt = salt
	}
}

// WithSaltString() runs the salt string through hex.DecodeString() to derive a
// byte slice that, if at least 32 bytes long, is used instead of the default
// internal fixed salt. Not recommended as it just nils the salt on error, use
// WithSalt() and solve decoding with e.g hex.DecodeString() prior to instance
// creation. You can also use SetSaltFromString() on the instance after New().
func WithSaltString(salt string) Option {
	bsalt, err := hex.DecodeString(salt)
	if err != nil || len(bsalt) < MinimumSaltLength {
		return func(k *Krypto431) {
			k.salt = nil
		}
	}
	return func(k *Krypto431) {
		k.salt = &bsalt
	}
}

func WithCallSign(cs string) Option {
	return func(k *Krypto431) {
		k.SetCallSign(cs)
	}
}

func WithMutex(mu *sync.Mutex) Option {
	return func(k *Krypto431) {
		k.mx = mu
	}
}
func WithGroupSize(n int) Option {
	return func(k *Krypto431) {
		k.GroupSize = n
	}
}
func WithKeyLength(n int) Option {
	return func(k *Krypto431) {
		k.KeyLength = n
	}
}
func WithColumns(n int) Option {
	return func(k *Krypto431) {
		k.Columns = n
	}
}
func WithKeyColumns(n int) Option {
	return func(k *Krypto431) {
		k.KeyColumns = n
	}
}
func WithPersistence(savefile string) Option {
	return func(k *Krypto431) {
		k.persistence = savefile
	}
}
func WithOverwritePersistenceIfExists(b bool) Option {
	return func(k *Krypto431) {
		k.overwritePersistenceIfExists = b
	}
}
func WithInteractive(b bool) Option {
	return func(k *Krypto431) {
		k.interactive = b
	}
}

// Methods assigned to the main struct...

// Asserts that settings in the instance are valid. Function is intended to be
// executed after New() to assert that settings are valid.
func (k *Krypto431) Assert() error {
	if len(k.persistence) == 0 {
		return ErrNoPersistence
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

// SetInteractive is provided to set the interactive non-exported field in an
// instance (true=on, false=off).
func (k *Krypto431) SetInteractive(state bool) {
	k.interactive = state
}

// Validates and sets the instance's call-sign.
func (k *Krypto431) SetCallSign(callsign string) error {
	cs := []rune(strings.ToUpper(strings.TrimSpace(callsign)))
	if len(cs) < MinimumCallSignLength {
		return ErrInvalidCallSign
	}
	k.CallSign = cs
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
	// wipe persistenceKey
	WipeBytes(k.persistenceKey)
	// wipe salt
	WipeBytes(k.salt)
}
