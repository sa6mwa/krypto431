package krypto431

import "sync"

// defaults
const (
	defaultGroupSize     int  = 5
	defaultKeyLength     int  = 200
	defaultMakePDF       bool = false
	defaultMakeTextFiles bool = false
)

// There are 4 states in Krypto431. These are used with bitwise operators.
const (
	StateInitialized uint8 = 1 << iota
	StateAlternateTable
	StateLowerCase
	StateKeyChange
	StateUninitialized uint8 = 0
)

// main struct
type Krypto431 struct {
	Mu            sync.Mutex
	GroupSize     int
	KeyLength     int
	Results       []Result
	MakePDF       bool
	MakeTextFiles bool
	state         uint8
}

type Key struct {
	Bytes []byte
}

// Key.Wipe() zeroes a key.
func (k *Key) Wipe() {
	for i := 0; i < len(k); i++ {
		k.Bytes[i] = 0
	}
	k.Bytes = nil
}

// Result is returned for keys, encoded/decoded plaintext, encrypted ciphertext
// and decrypted plaintext. Pointers to result is added to Krypto431.Results[]
// and wiped when Krypto431.Close() is called.
type Result struct {
	GroupCount int
	Keys       []Key
	CipherText []byte
	PlainText  []byte
}

// Result.Wipe() overwrites the underlying keys, plaintext and ciphertext with
// zeroes. The order is highest priority first (keys) followed by the plaintext
// and finally the ciphertext. Nilling the byte slices should promote it for
// garbage collection.
func (r *Result) Wipe() {
	for i := range r.Keys {
		r.Keys[i].Wipe()
	}
	for i := 0; i < len(r.PlainText); i++ {
		r.PlainText[i] = 0
	}
	r.PlainText = nil
	for i := 0; i < len(r.CipherText); i++ {
		r.CipherText[i] = 0
	}
	r.CipherText = nil
}

func New(opts ...Option) Krypto431 {
	k := &Krypto431{
		GroupSize:     defaultGroupSize,
		KeyLength:     defaultKeyLength,
		MakePDF:       defaultMakePDF,
		MakeTextFiles: defaultMakeTextFiles,
		state:         StateUninitialized,
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
func WithMakePDF(b bool) Option {
	return func(k *Krypto431) {
		k.MakePDF = true
	}
}
func WithMakeTextFiles(b bool) Option {
	return func(k *Krypto431) {
		k.MakeTextFiles = true
	}
}

// Methods assigned to the main struct, start of API...

func (k *Krypto431) Close() {
	k.Wipe()
}
func (k *Krypto431) Wipe() {
	for i := range k.Results {
		k.Results[i].Wipe()
	}
}

// TODO: Implement! :)

func (k *Krypto431) Encode(plaintext string) {}
func (k *Krypto431) Decode(plaintext string) {}

func (k *Krypto431) Encrypt(plaintext string)  {}
func (k *Krypto431) Decrypt(ciphertext string) {}

func (k *Krypto431) EncryptFile(path string) {}
func (k *Krypto431) DecryptFile(path string) {}

func (k *Krypto431) GenerateOneKey() (Result, error) {
	// Output: result struct with key, error/nil
	return &Result{}, nil
}

func (k *Krypto431) GenerateKeys(n int) (Result, error) {
	return &Result{}, nil
}
