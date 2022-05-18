package krypto431

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math"
	"sync"

	"github.com/sa6mwa/krypto431/crand"
)

// Krypto431 is the interface. Each struct must have these assigned methods.
type Krypto431 interface {
	Wipe()
	RandomWipe()
	ZeroWipe()
	Groups()
	GroupsBlock()
}

// defaults
const (
	defaultGroupSize     int  = 5
	defaultKeyLength     int  = 280 // same as Twitter
	defaultColumns       int  = 80
	defaultMakePDF       bool = false
	defaultMakeTextFiles bool = false
	useCrandWipe         bool = true
	DefaultKeyCapacity   int  = 280
	DefaultTextCapacity  int  = defaultKeyLength * 20 // 5600
)

// Instance stores generated keys, plaintext, ciphertext, callsign(s) and
// configuration items. It is mandatory to populate MyCallSigns with at least
// one call sign (something identifying yourself in message handling). It will
// be converted to upper case.
type Instance struct {
	Mu            *sync.Mutex
	GroupSize     int       `json:",omitempty"`
	KeyLength     int       `json:",omitempty"`
	Columns       int       `json:",omitempty"`
	Keys          []Key     `json:",omitempty"`
	Texts         []Text    `json:",omitempty"`
	MakePDF       bool      `json:",omitempty"`
	MakeTextFiles bool      `json:",omitempty"`
	MyCallSigns   *[][]rune `json:",omitempty"`
}

// Key struct holds a key. Keepers is a list of callsigns or other identifiers
// that have access to this key (and can use it for encryption/decryption). The
// proper procedure is to share the key with it's respective keeper(s). By
// default, all your callsigns (MyCallSigns) will be appended to the Keepers
// slice.
type Key struct {
	Id        []rune   `json:",omitempty"`
	Runes     []rune   `json:",omitempty"`
	Keepers   [][]rune `json:",omitempty"`
	Used      bool     `json:",omitempty"`
	Decrypted bool
	instance  *Instance
}

// Text holds plaintext and ciphertext. To encrypt, you need to populate the
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
type Text struct {
	GroupCount int      `json:",omitempty"`
	KeyId      []rune   `json:",omitempty"`
	PlainText  []rune   `json:",omitempty"`
	Binary     []byte   `json:",omitempty"`
	CipherText []rune   `json:",omitempty"`
	Recipients [][]rune `json:",omitempty"`
	Decrypted  bool
	instance   *Instance
}

// Wipe wipes a rune slice.
func Wipe(b *[]rune) error {
	if b == nil {
		return errors.New("Received a nil pointer")
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
		return errors.New("Received a nil pointer")
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
		return errors.New("Received a nil pointer")
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
	if k == nil {
		return errors.New("Received a nil pointer")
	}
	runeSlices := []*[]rune{&k.Runes, &k.Id}
	for i := range runeSlices {
		written, err := crand.ReadRunes(*runeSlices[i])
		if err != nil || written != len(*runeSlices[i]) {
			if err != nil {
				log.Println(err.Error())
			}
			log.Printf("ERROR, wrote %d runes, but expected to write %d", written, len(*runeSlices[i]))
			// zero-wipe rune slice instead...
			for i := 0; i < len(*runeSlices[i]); i++ {
				*runeSlices[i] = []rune{0}
			}
		}
		*runeSlices[i] = nil
	}
	return nil
}

// ZeroWipe zeroes a key.
func (k *Key) ZeroWipe() error {
	if k == nil {
		return errors.New("Received a nil pointer")
	}
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

// groups returns a rune slice where each group is
// separated by a space. Don't forget to Wipe(myRuneSlice) when you are
// done!
func groups(input *[]rune, groupsize int) (*[]rune, error) {
	if input == nil {
		return nil, errors.New("Input must not be a nil pointer")
	}
	if groupsize <= 0 {
		return nil, errors.New("Groupsize must be above 0")
	}
	output := make([]rune, 0, int(math.Ceil(float64(len(*input))/float64(groupsize)))*(groupsize+1))
	runeCount := 0
	for i := 0; i < len(*input); i++ {
		output = append(output, (*input)[i])
		runeCount++
		if runeCount == groupsize {
			if i != len(*input)-1 {
				output = append(output, rune(' '))
			}
			runeCount = 0
		}
	}
	return &output, nil
}

// Groups appends runes into the target slice into groups of GroupSize runes
// separated by space. Don't forget to Wipe(target) this slice when you are
// done!
func (k *Key) Groups() (*[]rune, error) {
	return groups(&k.Runes, k.instance.GroupSize)
}

// Groups assigned method returns a []rune where each group is separated by
// space.
func (t *Text) Groups() (*[]rune, error) {
	// There is no need to group the Text (non-encoded) field.
	return groups(&t.CipherText, t.instance.GroupSize)
}

// GroupsBlock returns a string representation of the key where each group is
// separated by a space and new lines if the block is longer than
// Instance.Columns (or defaultColumns). Don't forget to Wipe(b []rune) this
// slice when you are done!
func (k *Key) GroupsBlock() (*[]rune, error) {
	return nil, nil
}

// GroupsBlock for Text
func (t *Text) GroupsBlock() (*[]rune, error) {
	return nil, nil
}

// Wipe overwrites key, plaintext and ciphertext with random runes or zeroes.
// The order is highest priority first (plaintext), then ciphertext and finally
// the groupcount and keyid. Nilling the rune slices should promote it for
// garbage collection.
func (t *Text) Wipe() {
	if useCrandWipe {
		t.RandomWipe()
	} else {
		t.ZeroWipe()
	}
}

// RandomWipe assigned method for Text wipes PlainText, CipherText, GroupCount
// and KeyId fields.
func (t *Text) RandomWipe() {
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
}

// ZeroWipe assigned method for PlainText writes zeroes to Text and EncodedText
// fields.
func (t *Text) ZeroWipe() {
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
}

// New creates a new Instance construct
func New(opts ...Option) Instance {
	i := Instance{
		GroupSize:     defaultGroupSize,
		KeyLength:     defaultKeyLength,
		Columns:       defaultColumns,
		MakePDF:       defaultMakePDF,
		MakeTextFiles: defaultMakeTextFiles,
		Keys:          make([]Key, 0, DefaultKeyCapacity),
		Texts:         make([]Text, 0, DefaultTextCapacity),
	}
	for _, opt := range opts {
		opt(&i)
	}
	if i.Mu == nil {
		i.Mu = &sync.Mutex{}
	}
	if i.MyCallSigns == nil {
		// KA = Kilo Alpha = Kalle Anka = Donald Duck
		defaultCallSigns := [][]rune{[]rune("KA")}
		i.MyCallSigns = &defaultCallSigns
	}
	return i
}

// Option fn type for the New() construct.
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
		r.Mu = mu
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

// AllNeedlesInHaystack returns true is all needles can be found in the
// haystack, but if one slice in the haystack is a star (*) it will always
// return true. Intended to find Keepers of Keys where needles are
// Text.Recipients and haystack is Key.Keepers.
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
	for i := range r.Texts {
		r.Texts[i].Wipe()
	}
	r.Texts = nil
}

func (r *Instance) Save() {
	j, err := json.Marshal(r)
	if err != nil {
		panic(err)
	}
	fmt.Println(string(j))
}

// TODO: Implement! :)

//func (r *Instance) Encode(plaintext string) {}
//func (r *Instance) Decode(plaintext string) {}

func (r *Instance) EncryptFile(path string) {}
func (r *Instance) DecryptFile(path string) {}
