package krypto

import (
	"log"
	"sync"

	"github.com/sa6mwa/krypto431/pkg/crand"
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
	defaultKeyLength     int  = 200
	defaultColumns       int  = 80
	defaultMakePDF       bool = false
	defaultMakeTextFiles bool = false
	useCrandWipe         bool = true
)

// Instance stores most of the generated keys, encoded/decoded plain and
// ciphertext in Krypto431.
type Instance struct {
	Mu            *sync.Mutex
	GroupSize     int
	KeyLength     int
	Columns       int
	Keys          []Key
	PlainTexts    []PlainText
	CipherTexts   []CipherText
	MakePDF       bool
	MakeTextFiles bool
}

// Key struct holds a key.
type Key struct {
	ID       []rune
	Runes    []rune
	instance *Instance
}

// PlainText holds plaintext messages and plaintext encoded text (encryption
// flow is: Text, EncodedText, CipherText.Text.
type PlainText struct {
	GroupCount  int
	KeyID       []rune
	Text        []rune
	EncodedText []rune
	instance    *Instance
}

// CipherText holds encrypted text ready for decryption.
type CipherText struct {
	GroupCount int
	KeyID      []rune
	Text       []rune
	instance   *Instance
}

// Wipe wipes a rune slice.
func Wipe(b *[]rune) {
	if useCrandWipe {
		err := RandomWipe(b)
		if err != nil {
			panic(err)
		}
	} else {
		ZeroWipe(b)
	}
}

// RandomWipe wipes a rune slice with random runes.
func RandomWipe(b *[]rune) error {
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
func ZeroWipe(b *[]rune) {
	for i := range *b {
		(*b)[i] = 0
	}
	*b = nil
}

// Wipe overwrites key with either random runes or zeroes.
func (k *Key) Wipe() {
	if useCrandWipe {
		k.RandomWipe()
	} else {
		k.ZeroWipe()
	}
}

// RandomWipe overwrites key with random runes.
func (k *Key) RandomWipe() {
	written, err := crand.ReadRunes(k.Runes)
	if err != nil || written != len(k.Runes) {
		if err != nil {
			log.Println(err.Error())
		}
		log.Printf("ERROR, wrote %d runes, but expected to write %d", written, len(k.Runes))
		k.ZeroWipe()
	}
	k.Runes = nil
}

// ZeroWipe zeroes a key.
func (k *Key) ZeroWipe() {
	for i := 0; i < len(k.Runes); i++ {
		k.Runes[i] = 0
	}
	k.Runes = nil
}

// groups(input []rune, groupsize int) returns a rune slice where each group is
// separated by a space. Don't forget to Wipe(b []rune) this slice when you are
// done!
func groups(input *[]rune, groupsize int) (r []rune) {
	runeCount := 0
	for i := 0; i < len(*input); i++ {
		r = append(r, (*input)[i])
		runeCount++
		if runeCount == groupsize {
			if i != len(*input)-1 {
				r = append(r, rune(' '))
			}
			runeCount = 0
		}
	}
	return
}

// Groups returns a []rune where each group is separated by space. Don't forget
// to Wipe(b []rune) this slice when you are done!
func (k *Key) Groups() []rune {
	return groups(&k.Runes, k.instance.GroupSize)
}

// Groups assigned method returns a []rune where each group is separated by
// space.
func (p *PlainText) Groups() []rune {
	// There is no need to group the Text (non-encoded) field.
	return groups(&p.EncodedText, p.instance.GroupSize)
}

// Groups assigned method returns a []rune where each group is separated by
// space.
func (c *CipherText) Groups() []rune {
	return groups(&c.Text, c.instance.GroupSize)
}

// GroupsBlock returns a string representation of the key where each group is
// separated by a space and new lines if the block is longer than
// Instance.Columns (or defaultColumns). Don't forget to Wipe(b []rune) this
// slice when you are done!
func (k *Key) GroupsBlock() []rune {
	return []rune("Hello world, implement me!")
}

// GroupsBlock for PlainText
func (p *PlainText) GroupsBlock() []rune {
	return []rune("HELLO WORLD")
}

// GroupsBlock for CipherText
func (c *CipherText) GroupsBlock() []rune {
	return []rune("HELLO WORLD")
}

// Wipe overwrites key, plaintext and ciphertext with random runes or zeroes.
// The order is highest priority first (plaintext), then ciphertext and finally
// the groupcount and keyid. Nilling the rune slices should promote it for
// garbage collection.
func (p *PlainText) Wipe() {
	if useCrandWipe {
		p.RandomWipe()
	} else {
		p.ZeroWipe()
	}
}

// Wipe wipes CipherText.
func (c *CipherText) Wipe() {
	if useCrandWipe {
		c.RandomWipe()
	} else {
		c.ZeroWipe()
	}
}

// RandomWipe assigned method for PlainText wipes Text, EncodedText, GroupCount
// and KeyID fields.
func (p *PlainText) RandomWipe() {
	// wipe PlainText
	written, err := crand.ReadRunes(p.Text)
	if err != nil || written != len(p.Text) {
		for i := 0; i < len(p.Text); i++ {
			p.Text[i] = 0
		}
	}
	p.Text = nil
	// wipe EncodedText
	written, err = crand.ReadRunes(p.EncodedText)
	if err != nil || written != len(p.EncodedText) {
		for i := 0; i < len(p.EncodedText); i++ {
			p.EncodedText[i] = 0
		}
	}
	p.EncodedText = nil
	// wipe GroupCount
	p.GroupCount = crand.Int()
	// wipe KeyID
	written, err = crand.ReadRunes(p.KeyID)
	if err != nil || written != len(p.KeyID) {
		for i := 0; i < len(p.KeyID); i++ {
			p.KeyID[i] = 0
		}
	}
	p.KeyID = nil
}

// RandomWipe assigned method for CipherText wipes the Text, GroupCount and
// KeyID fields.
func (c *CipherText) RandomWipe() {
	// wipe CipherText
	written, err := crand.ReadRunes(c.Text)
	if err != nil || written != len(c.Text) {
		for i := 0; i < len(c.Text); i++ {
			c.Text[i] = 0
		}
	}
	c.Text = nil
	// wipe GroupCount
	c.GroupCount = crand.Int()
	// wipe KeyID
	written, err = crand.ReadRunes(c.KeyID)
	if err != nil || written != len(c.KeyID) {
		for i := 0; i < len(c.KeyID); i++ {
			c.KeyID[i] = 0
		}
	}
	c.KeyID = nil
}

// ZeroWipe assigned method for PlainText writes zeroes to Text and EncodedText
// fields.
func (p *PlainText) ZeroWipe() {
	// wipe PlainText
	for i := 0; i < len(p.Text); i++ {
		p.Text[i] = 0
	}
	p.Text = nil
	// wipe EncodedText
	for i := 0; i < len(p.EncodedText); i++ {
		p.EncodedText[i] = 0
	}
	p.EncodedText = nil
	// wipe GroupCount
	p.GroupCount = 0
	// wipe KeyID
	for i := 0; i < len(p.KeyID); i++ {
		p.KeyID[i] = 0
	}
	p.KeyID = nil
}

// ZeroWipe assigned method for CipherText writes zeroes to the Text field.
func (c *CipherText) ZeroWipe() {
	// wipe CipherText
	for i := 0; i < len(c.Text); i++ {
		c.Text[i] = 0
	}
	c.Text = nil
	// wipe GroupCount
	c.GroupCount = 0
	// wipe KeyID
	for i := 0; i < len(c.KeyID); i++ {
		c.KeyID[i] = 0
	}
	c.KeyID = nil
}

// New creates a new Instance construct
func New(opts ...Option) Instance {
	i := Instance{
		GroupSize:     defaultGroupSize,
		KeyLength:     defaultKeyLength,
		Columns:       defaultColumns,
		MakePDF:       defaultMakePDF,
		MakeTextFiles: defaultMakeTextFiles,
	}
	for _, opt := range opts {
		opt(&i)
	}
	if i.Mu == nil {
		i.Mu = &sync.Mutex{}
	}
	return i
}

// Option fn type for the New() construct.
type Option func(r *Instance)

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
	for i := range r.PlainTexts {
		r.PlainTexts[i].Wipe()
	}
	for i := range r.CipherTexts {
		r.CipherTexts[i].Wipe()
	}
}

// TODO: Implement! :)

func (r *Instance) Encode(plaintext string) {}
func (r *Instance) Decode(plaintext string) {}

func (r *Instance) Encrypt(plaintext string)  {}
func (r *Instance) Decrypt(ciphertext string) {}

func (r *Instance) EncryptFile(path string) {}
func (r *Instance) DecryptFile(path string) {}
