package krypto431

import (
	"compress/gzip"
	"encoding/gob"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"math"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/sa6mwa/krypto431/crand"
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
)

// Krypto431 is the interface. Each struct must have these assigned methods.
type Krypto431 interface {
	Wipe()
	RandomWipe()
	ZeroWipe()
	Groups()
	GroupsBlock()
}

// defaults, most are exported
const (
	useCrandWipe               bool   = true
	DefaultGroupSize           int    = 5
	DefaultKeyLength           int    = 350 // 70 groups, 5 groups per row is 14 rows total
	DefaultColumns             int    = 80
	DefaultMakePDF             bool   = false
	DefaultMakeTextFiles       bool   = false
	DefaultSaveFile            string = "~/.krypto431.gob"
	DefaultKeyCapacity         int    = 50000                                   // 50k keys
	DefaultChunkCapacity       int    = 20                                      // 20 chunks
	DefaultEncodedTextCapacity int    = DefaultKeyLength * 2                    // 700
	DefaultMessageCapacity     int    = 10000                                   // 10k messages
	DefaultPlainTextCapacity   int    = DefaultKeyLength * DefaultChunkCapacity // 7000
)

// Instance stores generated keys, plaintext, ciphertext, callsign(s) and
// configuration items. It is mandatory to populate MyCallSigns with at least
// one call sign (something identifying yourself in message handling). It will
// be converted to upper case. Mutex and persistance file (saveFile) are not
// exported meaning values will not be persisted to disk.
type Instance struct {
	mx                       *sync.Mutex
	saveFile                 string
	createSaveFileIfNotExist bool
	GroupSize                int       `json:",omitempty"`
	KeyLength                int       `json:",omitempty"`
	Columns                  int       `json:",omitempty"`
	Keys                     []Key     `json:",omitempty"`
	Messages                 []Message `json:",omitempty"`
	MakePDF                  bool      `json:",omitempty"`
	MakeTextFiles            bool      `json:",omitempty"`
	MyCallSigns              *[][]rune `json:",omitempty"`
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
	Used     bool     `json:",omitempty"`
	instance *Instance
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
	GroupCount int    `json:",omitempty"`
	KeyId      []rune `json:",omitempty"`
	PlainText  []rune `json:",omitempty"`
	Binary     []byte `json:",omitempty"`
	CipherText []rune `json:",omitempty"`
	//EncodedChunks []Chunk  `json:",omitempty"`
	Recipients [][]rune `json:",omitempty"`
	instance   *Instance
}

// A chunk is either the complete PlainText encoded or - if the message is too
// long for the key - part of the PlainText where all but the last chunk ends in
// a key change. Each chunk is to be enciphered with a key allowing to chain
// multiple keys for longer messages.
type Chunk struct {
	EncodedText []rune `json:",omitempty"`
	KeyId       []rune `json:",omitempty"`
}

// Returns an initialized Chunk (groupsize is usually msg.instance.GroupSize).
func NewChunk(groupSize int) Chunk {
	return Chunk{
		EncodedText: make([]rune, 0, DefaultEncodedTextCapacity),
		KeyId:       make([]rune, 0, groupSize),
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
// Instance.Columns (or defaultColumns). Don't forget to Wipe(b []rune) this
// slice when you are done!
func (k *Key) GroupsBlock() (*[]rune, error) {
	return groups(&k.Runes, k.instance.GroupSize, k.instance.Columns)
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
func (c *Chunk) Wipe() error {
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
func (c *Chunk) RandomWipe() error {
	runeSlices := []*[]rune{&c.EncodedText, &c.KeyId}
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
func (c *Chunk) ZeroWipe() error {
	for i := 0; i < len(c.EncodedText); i++ {
		c.EncodedText[i] = 0
	}
	c.EncodedText = nil
	for i := 0; i < len(c.KeyId); i++ {
		c.KeyId[i] = 0
	}
	c.KeyId = nil
	return nil
}

// New creates a new Instance construct
func New(opts ...Option) Instance {
	i := Instance{
		saveFile:                 DefaultSaveFile,
		createSaveFileIfNotExist: false,
		GroupSize:                DefaultGroupSize,
		KeyLength:                DefaultKeyLength,
		Columns:                  DefaultColumns,
		MakePDF:                  DefaultMakePDF,
		MakeTextFiles:            DefaultMakeTextFiles,
		Keys:                     make([]Key, 0, DefaultKeyCapacity),
		Messages:                 make([]Message, 0, DefaultMessageCapacity),
	}
	for _, opt := range opts {
		opt(&i)
	}
	if i.mx == nil {
		i.mx = &sync.Mutex{}
	}
	if i.MyCallSigns == nil {
		// KA = Kilo Alpha = Kalle Anka = Donald Duck
		defaultCallSigns := [][]rune{[]rune("KA")}
		i.MyCallSigns = &defaultCallSigns
	}
	return i
}

// Option fn type for the New() and Load() constructs.
type Option func(r *Instance)

func WithCallSign(cs *[]rune) Option {
	return func(r *Instance) {
		*r.MyCallSigns = append(*r.MyCallSigns, *cs)
	}
}
func WithCallSigns(css *[][]rune) Option {
	return func(r *Instance) {
		r.MyCallSigns = css
	}
}
func WithMutex(mu *sync.Mutex) Option {
	return func(r *Instance) {
		r.mx = mu
	}
}
func WithGroupSize(n int) Option {
	return func(r *Instance) {
		r.GroupSize = n
	}
}
func WithKeyLength(n int) Option {
	return func(r *Instance) {
		r.KeyLength = n
	}
}
func WithColumns(n int) Option {
	return func(r *Instance) {
		r.Columns = n
	}
}
func WithMakePDF(b bool) Option {
	return func(r *Instance) {
		r.MakePDF = b
	}
}
func WithMakeTextFiles(b bool) Option {
	return func(r *Instance) {
		r.MakeTextFiles = b
	}
}

func WithSaveFile(savefile string) Option {
	return func(r *Instance) {
		r.saveFile = savefile
	}
}

func WithCreateSaveFileIfNotExist() Option {
	return func(r *Instance) {
		r.createSaveFileIfNotExist = true
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

// Methods assigned to the main struct, start of API...

// Close is an alias for Instance.Wipe()
func (r *Instance) Close() {
	r.Wipe()
}

// Wipe instance assigned method wipes all in-memory keys and texts (plaintext
// and ciphertext) with random runes or zeroes in an attempt to keep sensitive
// information for as short time as possible in memory. Whenever keys or
// ciphertexts are written to the database they are wiped automatically,
// respectively, but it is up to the user of the API to call Wipe() or Close()
// when using the methods to read keys and ciphertext from database, file or
// stdin when done processing them.
func (r *Instance) Wipe() {
	for i := range r.Keys {
		r.Keys[i].Wipe()
	}
	r.Keys = nil
	for i := range r.Messages {
		r.Messages[i].Wipe()
	}
	r.Messages = nil
}

// TODO: Try https://github.com/nknorg/encrypted-stream for encrypting file before gzip...
func (r *Instance) Save() error {
	if len(r.saveFile) == 0 {
		return fmt.Errorf("can not save: missing file name for persisting keys, messages and settings")
	}
	// If save file starts with a tilde, resolve it to the user's home directory.
	if strings.HasPrefix(r.saveFile, "~/") {
		dirname, err := os.UserHomeDir()
		if err != nil {
			return err
		}
		r.saveFile = filepath.Join(dirname, r.saveFile[2:])
	}
	// Create save file if it does not exist or truncate it if it does exist.
	f, err := os.OpenFile(r.saveFile, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	// Krypto431 save files are gzipped GOB files.
	fgz := gzip.NewWriter(f)
	defer fgz.Close()
	gobEncoder := gob.NewEncoder(fgz)
	err = gobEncoder.Encode(r)
	if err != nil {
		return err
	}
	return nil
}

func (r *Instance) Load() error {
	if len(r.saveFile) == 0 {
		return fmt.Errorf("missing file name for persisting keys, messages and settings")
	}
	// If save file starts with a tilde, resolve it to the user's home directory.
	if strings.HasPrefix(r.saveFile, "~/") {
		dirname, err := os.UserHomeDir()
		if err != nil {
			return err
		}
		r.saveFile = filepath.Join(dirname, r.saveFile[2:])
	}

	var f *os.File
	_, err := os.Stat(r.saveFile)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) && r.createSaveFileIfNotExist {
			err = r.Save()
			if err != nil {
				return err
			}
		} else {
			return err
		}
	} else {
		// Save file does exist, load it...
		f, err = os.Open(r.saveFile)
		if err != nil {
			return err
		}
		defer f.Close()
		fgz, err := gzip.NewReader(f)
		if err != nil {
			return err
		}
		defer fgz.Close()
		gobDecoder := gob.NewDecoder(fgz)
		err = gobDecoder.Decode(r)
		if err != nil {
			return err
		}
		// Fix all unexported instance fields in keys and messages
		for i := range r.Keys {
			r.Keys[i].instance = r
		}
		for i := range r.Messages {
			r.Messages[i].instance = r
		}
	}
	return nil
}

// NewTextMessage() is a variadic function where first argument is the message,
// second is a comma-separated list with recipients, third a key id to override
// the key finder function and use a specific key (not marked "used"). First
// argument is mandatory, rest are optional.
func (r *Instance) NewTextMessage(msg ...string) (err error) {
	// 1st arg = message as a utf8 string (mandatory)
	// 2nd arg = recipients as a comma-separated list (optional)
	// 3rd arg = key id, overrides the key finder function (optional)

	if len(msg) == 0 {
		return errors.New("must at least provide the message text (first argument)")
	}

	message := Message{
		PlainText: []rune(strings.TrimSpace(msg[0])),
		instance:  r,
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
		if len(message.KeyId) != r.GroupSize {
			return fmt.Errorf("key id \"%s\" must be %d characters long (the configured group size)", string(message.KeyId), r.GroupSize)
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
	r.Messages = append(r.Messages, message)
	return nil
}

// TODO: Implement! :)

//func (r *Instance) NewBinaryMessage()

//func (r *Instance) Encode(plaintext string) {}
//func (r *Instance) Decode(plaintext string) {}

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
