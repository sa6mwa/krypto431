package krypto

import (
	"log"
	"sync"

	"github.com/sa6mwa/krypto431/pkg/crand"
)

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

// main struct
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

type Key struct {
	Id       []byte
	Bytes    []byte
	instance *Instance
}

type PlainText struct {
	GroupCount  int
	KeyId       []byte
	Text        []byte
	EncodedText []byte
	instance    *Instance
}

type CipherText struct {
	GroupCount int
	KeyId      []byte
	Text       []byte
	instance   *Instance
}

// Wipe(b []byte) wipes a byte slice.
func Wipe(b []byte) {
	if useCrandWipe {
		RandomWipe(b)
	} else {
		ZeroWipe(b)
	}
}

// RandomWipe(b []byte) wipes a byte slice with random bytes.
func RandomWipe(b []byte) error {
	written, err := crand.Read(b)
	if err != nil || written != len(b) {
		if err != nil {
			return err
		}
		ZeroWipe(b)
	}
	b = nil
	return nil
}

// ZeroWipe(b []byte) wipes a byte slice with zeroes.
func ZeroWipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
	b = nil
}

// Key.Wipe() overwrites key with either random bytes or zeroes.
func (k *Key) Wipe() {
	if useCrandWipe {
		k.RandomWipe()
	} else {
		k.ZeroWipe()
	}
}

// Key.RandomWipe() overwrites key with random bytes.
func (k *Key) RandomWipe() {
	written, err := crand.Read(k.Bytes)
	if err != nil || written != len(k.Bytes) {
		if err != nil {
			log.Println(err.Error())
		}
		log.Printf("ERROR, wrote %d bytes, but expected to write %d", written, len(k.Bytes))
		k.ZeroWipe()
	}
	k.Bytes = nil
}

// Key.ZeroWipe() zeroes a key.
func (k *Key) ZeroWipe() {
	for i := 0; i < len(k.Bytes); i++ {
		k.Bytes[i] = 0
	}
	k.Bytes = nil
}

// groups(input []byte, groupsize int) returns a byte slice where each group is
// separated by a space. Don't forget to Wipe(b []byte) this slice when you are
// done!
func groups(input []byte, groupsize int) []byte {
	var b []byte
	byteCount := 0
	for i := 0; i < len(input); i++ {
		b = append(b, input[i])
		byteCount++
		if byteCount == groupsize {
			if i != len(input)-1 {
				b = append(b, byte(' '))
			}
			byteCount = 0
		}
	}
	return b
}

// Key.Groups() returns a []byte where each group is separated by space. Don't
// forget to Wipe(b []byte) this slice when you are done!
func (k *Key) Groups() []byte {
	return groups(k.Bytes, k.instance.GroupSize)
}

func (p *PlainText) Groups() []byte {
	// There is no need to group the Text (non-encoded) field.
	return groups(p.EncodedText, p.instance.GroupSize)
}

func (c *CipherText) Groups() []byte {
	return groups(c.Text, c.instance.GroupSize)
}

// GroupsBlock() returns a string representation of the key where each group is
// separated by a space and new lines if the block is longer than
// Instance.Columns (or defaultColumns). Don't forget to Wipe(b []byte) this
// slice when you are done!
func (k *Key) GroupsBlock() []byte {
	return []byte("Hello world, implement me!")
}
func (p *PlainText) GroupsBlock() []byte {
	return []byte("HELLO WORLD")
}
func (c *CipherText) GroupsBlock() []byte {
	return []byte("HELLO WORLD")
}

// Wipe() overwrites key, plaintext and ciphertext with random bytes or zeroes.
// The order is highest priority first (plaintext), then ciphertext and finally
// the groupcount and keyid. Nilling the byte slices should promote it for
// garbage collection.
func (p *PlainText) Wipe() {
	if useCrandWipe {
		p.RandomWipe()
	} else {
		p.ZeroWipe()
	}
}

func (c *CipherText) Wipe() {
	if useCrandWipe {
		c.RandomWipe()
	} else {
		c.ZeroWipe()
	}
}

// RandomWipe()
func (p *PlainText) RandomWipe() {
	// wipe PlainText
	written, err := crand.Read(p.Text)
	if err != nil || written != len(p.Text) {
		for i := 0; i < len(p.Text); i++ {
			p.Text[i] = 0
		}
	}
	p.Text = nil
	// wipe EncodedText
	written, err = crand.Read(p.EncodedText)
	if err != nil || written != len(p.EncodedText) {
		for i := 0; i < len(p.EncodedText); i++ {
			p.EncodedText[i] = 0
		}
	}
	p.EncodedText = nil
	// wipe GroupCount
	p.GroupCount = crand.Int()
	// wipe KeyId
	written, err = crand.Read(p.KeyId)
	if err != nil || written != len(p.KeyId) {
		for i := 0; i < len(p.KeyId); i++ {
			p.KeyId[i] = 0
		}
	}
	p.KeyId = nil
}

func (c *CipherText) RandomWipe() {
	// wipe CipherText
	written, err := crand.Read(c.Text)
	if err != nil || written != len(c.Text) {
		for i := 0; i < len(c.Text); i++ {
			c.Text[i] = 0
		}
	}
	c.Text = nil
	// wipe GroupCount
	c.GroupCount = crand.Int()
	// wipe KeyId
	written, err = crand.Read(c.KeyId)
	if err != nil || written != len(c.KeyId) {
		for i := 0; i < len(c.KeyId); i++ {
			c.KeyId[i] = 0
		}
	}
	c.KeyId = nil
}

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
	// wipe KeyId
	for i := 0; i < len(p.KeyId); i++ {
		p.KeyId[i] = 0
	}
	p.KeyId = nil
}

func (c *CipherText) ZeroWipe() {
	// wipe CipherText
	for i := 0; i < len(c.Text); i++ {
		c.Text[i] = 0
	}
	c.Text = nil
	// wipe GroupCount
	c.GroupCount = 0
	// wipe KeyId
	for i := 0; i < len(c.KeyId); i++ {
		c.KeyId[i] = 0
	}
	c.KeyId = nil
}

// New construct
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

// Instance.Close() is an alias for Instance.Wipe()
func (r *Instance) Close() {
	r.Wipe()
}

// Instance.Wipe() wipes all in-memory keys and texts (plaintext and
// ciphertext) with random bytes or zeroes in an attempt to keep sensitive
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
