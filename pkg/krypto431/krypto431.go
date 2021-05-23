package krypto431

import (
	"log"
	"sync"

	"github.com/sa6mwa/krypto431/pkg/crand"
)

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
type Krypto431 struct {
	Mu            sync.Mutex
	GroupSize     int
	KeyLength     int
	Columns       int
	Keys          []Key
	Texts         []Text
	MakePDF       bool
	MakeTextFiles bool
}

type Key struct {
	KeyId    []byte
	Bytes    []byte
	instance *Krypto431
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

func (t *Text) PlainTextGroups() []byte {
	return groups(t.PlainText, t.instance.GroupSize)
}

func (t *Text) CipherTextGroups() []byte {
	return groups(t.CipherText, t.instance.GroupSize)
}

// GroupsBlock() returns a string representation of the key where each group is
// separated by a space and new lines if the block is longer than
// Krypto431.Columns (or defaultColumns). Don't forget to Wipe(b []byte) this
// slice when you are done!
func (k *Key) GroupsBlock() []byte {
	return []byte("Hello world")
}

// Text pairs plaintext and ciphertext with a keyId. The first group of
// CipherText does not contain the key identifier (the first group of the key),
// but is added as prefix by assigned methods Text.Groups() and
// Text.GroupsBlock(). Each Text item is wiped when Krypto431.Wipe() or
// Krypto431.Close() is called.
type Text struct {
	GroupCount int
	KeyId      []byte
	CipherText []byte
	PlainText  []byte
	instance   *Krypto431
}

// Text.Wipe() overwrites plaintext and ciphertext with random bytes or
// zeroes. The order is highest priority first (plaintext), then ciphertext and
// finally the groupcount and keyid. Nilling the byte slices should promote it
// for garbage collection.
func (t *Text) Wipe() {
	if useCrandWipe {
		t.RandomWipe()
	} else {
		t.ZeroWipe()
	}
}

func (t *Text) RandomWipe() {
	// wipe PlainText
	written, err := crand.Read(t.PlainText)
	if err != nil || written != len(t.PlainText) {
		for i := 0; i < len(t.PlainText); i++ {
			t.PlainText[i] = 0
		}
	}
	t.PlainText = nil
	// wipe CipherText
	written, err = crand.Read(t.CipherText)
	if err != nil || written != len(t.CipherText) {
		for i := 0; i < len(t.CipherText); i++ {
			t.CipherText[i] = 0
		}
	}
	t.CipherText = nil
	// wipe GroupCount
	t.GroupCount = crand.Int()
	// wipe KeyId
	written, err = crand.Read(t.KeyId)
	if err != nil || written != len(t.KeyId) {
		for i := 0; i < len(t.KeyId); i++ {
			t.KeyId[i] = 0
		}
	}
	t.KeyId = nil
}

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

func New(opts ...Option) Krypto431 {
	k := &Krypto431{
		GroupSize:     defaultGroupSize,
		KeyLength:     defaultKeyLength,
		Columns:       defaultColumns,
		MakePDF:       defaultMakePDF,
		MakeTextFiles: defaultMakeTextFiles,
	}
	for _, opt := range opts {
		opt(k)
	}
	return *k
}

// Option fn type for the New() construct.
type Option func(k *Krypto431)

func WithMutex(mu sync.Mutex) Option {
	return func(k *Krypto431) {
		k.Mu = mu
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
func WithMakePDF(b bool) Option {
	return func(k *Krypto431) {
		k.MakePDF = b
	}
}
func WithMakeTextFiles(b bool) Option {
	return func(k *Krypto431) {
		k.MakeTextFiles = b
	}
}

// Methods assigned to the main struct, start of API...

// Krypto431.Close() is an alias for Krypto431.Wipe()
func (k *Krypto431) Close() {
	k.Wipe()
}

// Krypto431.Wipe() wipes all in-memory keys and texts (plaintext and
// ciphertext) with random bytes or zeroes in an attempt to keep sensitive
// information for as short time as possible in memory. Whenever keys or
// ciphertexts are written to the database they are wiped automatically,
// respectively, but it is up to the user of the API to call Wipe() or Close()
// when using the methods to read keys and ciphertext from database, file or
// stdin when done processing them.
func (k *Krypto431) Wipe() {
	for i := range k.Keys {
		k.Keys[i].Wipe()
	}
	for i := range k.Texts {
		k.Texts[i].Wipe()
	}
}

// TODO: Implement! :)

func (k *Krypto431) Encode(plaintext string) {}
func (k *Krypto431) Decode(plaintext string) {}

func (k *Krypto431) Encrypt(plaintext string)  {}
func (k *Krypto431) Decrypt(ciphertext string) {}

func (k *Krypto431) EncryptFile(path string) {}
func (k *Krypto431) DecryptFile(path string) {}
