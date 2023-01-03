package krypto431

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/gob"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"

	"github.com/AlecAivazis/survey/v2"
	stream "github.com/nknorg/encrypted-stream"
	"github.com/sa6mwa/krypto431/crand"
	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/term"
)

const (
	errUnableToDeriveKey string = "unable to derive key from password: "
)

var (
	RepeatPromptSuffix  string = "(repeat) "
	EncryptionPrompt    string = "Enter encryption key: "
	DecryptionPrompt    string = "Enter decryption key: "
	NewEncryptionPrompt string = "Enter new encryption key: "
)

var (
	ErrNoSalt           = errors.New(errUnableToDeriveKey + "instance is missing salt")
	ErrTooShortSalt     = errors.New(errUnableToDeriveKey + "salt is too short")
	ErrPasswordTooShort = fmt.Errorf(errUnableToDeriveKey+"too short, must be at least %d characters long", MinimumPasswordLength)
	ErrNilPFK           = errors.New("instance is missing key needed to encrypt or decrypt persistence")
	ErrInvalidPFK       = errors.New("persistence file key is invalid, must be 32 bytes long")
	ErrPasswordInput    = errors.New("password input error")
)

// DeriveKeyFromPassword uses PBKDF2 to produce the 32 byte long key used to
// encrypt/decrypt the persistence file. The salt in the Krypto431 instance is
// used to derive the key, either the default fixed salt or one that you
// provided earlier (e.g krypto431.New(krypto431.WithSalt(my64charHexString))).
func (k *Krypto431) DeriveKeyFromPassword(password *[]byte) error {
	if password == nil {
		return ErrNilPointer
	}
	defer WipeBytes(password)
	if k.salt == nil {
		return ErrNoSalt
	}
	if len(*k.salt) < MinimumSaltLength {
		return ErrTooShortSalt
	}
	if len(*password) < MinimumPasswordLength {
		return ErrPasswordTooShort
	}
	dk := pbkdf2.Key(*password, *k.salt, DefaultPBKDF2Iteration, 32, sha256.New)
	k.persistenceKey = &dk
	return nil
}

// GetPFK returns a byte slice pointer to the instance persistence file key
// (PFK). Function exists as the persistenceKey field is not exported.
func (k *Krypto431) GetPFK() *[]byte {
	return k.persistenceKey
}

// Similar to GetPFK, but return pointer to the salt.
func (k *Krypto431) GetSalt() *[]byte {
	return k.salt
}

// GetPFKString (yes, it's Pascal-case) returns a hex-encoded string
// representation of the persistence file key (or empty if there is no PFK in
// this instance). Function exists as the persistenceKey field is not exported.
func (k *Krypto431) GetPFKString() string {
	if k.persistenceKey == nil {
		return ""
	}
	return hex.EncodeToString(*k.persistenceKey)
}

// Similar to GetPFKString, but return a hex-encoded string of the salt.
func (k *Krypto431) GetSaltString() string {
	if k.salt == nil {
		return ""
	}
	return hex.EncodeToString(*k.salt)
}

// GetPersistence returns the non-exported persistence string (save-file) from
// an instance.
func (k *Krypto431) GetPersistence() string {
	return k.persistence
}

// SetPersistence sets the non-exported persistence property in the instance to
// filename.
func (k *Krypto431) SetPersistence(filename string) {
	k.persistence = filename
}

// Takes salt from a hex encoded string, converts it into a byte slice and sets
// it as the instance's salt for the password-based key derivative function used
// in Load() and Save(). Beware! If you loose the salt you used for encrypting
// your persistance-file it will be practically impossible to decrypt it even if
// you know the password.
func (k *Krypto431) SetSaltFromString(salt string) error {
	byteSalt, err := hex.DecodeString(salt)
	if err != nil {
		return err
	}
	if len(byteSalt) < MinimumSaltLength {
		WipeBytes(&byteSalt)
		return ErrTooShortSalt
	}
	k.salt = &byteSalt
	return nil
}

// Takes persistence file key (PFK) from a hex encoded string (from perhaps
// GeneratePFK()), converts it into a byte slice and sets it as the instance's
// PFK which will override the password-based key derivative function and the
// use of a salt. The key must be 32 bytes long (64 character long hex encoded
// string). GeneratePFK() is available to generate a new random persistence file
// key and return a hex encoded string. Beware that strings are immutable in Go
// which means the internal wipe functions can not be used to clear this
// sensitive string after closing or wiping the instance. The default
// password-based method use byte or rune slices which are (or can be) wiped in
// an attempt not to leave sensitive data around in memory after the program
// exits.
func (k *Krypto431) SetKeyFromString(key string) error {
	byteKey, err := hex.DecodeString(key)
	if err != nil {
		return err
	}
	if len(byteKey) != 32 {
		WipeBytes(&byteKey)
		return ErrInvalidPFK
	}
	k.persistenceKey = &byteKey
	return nil
}

// Similar to SetKeyFromString() except it derives the key from a passphrase via
// the PBKDF2 function DeriveKeyFromPassword(). The instance's configured salt
// is used and need to be set before calling this function.
func (k *Krypto431) SetKeyFromPassword(password string) error {
	byteKey := []byte(password)
	err := k.DeriveKeyFromPassword(&byteKey)
	if err != nil {
		return err
	}
	return nil
}

// AskForPassword prompts the user for a password/passphrase and returns a byte
// slice pointer or nil on error. The byte slice should be wiped with
// WipeBytes() as soon as a key has been derived from it.
func AskForPassword(prompt string, minimumLength int) *[]byte {
	fd := int(os.Stdin.Fd())
	oldState, err := term.GetState(fd)
	if err != nil {
		log.Fatal(err)
	}
	defer term.Restore(fd, oldState)
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, os.Interrupt, syscall.SIGTERM)
	go func() {
		for range ch {
			fmt.Fprintln(os.Stderr, "caught interrupt, exiting")
			term.Restore(fd, oldState)
			os.Exit(1)
		}
	}()
	// close() is necessary to stop the go routine, signal.Stop() is necessary to
	// prevent panic if signals should arrive on a closed channel.
	defer close(ch)
	defer signal.Stop(ch)
	var pw []byte
	for {
		fmt.Fprint(os.Stderr, prompt)
		pw, err = term.ReadPassword(int(syscall.Stdin))
		if err != nil {
			return nil
		}
		if len(pw) < minimumLength {
			fmt.Fprintf(os.Stderr, "\nPassphrase must be at least %d characters long, try again.\n", minimumLength)
		} else {
			fmt.Fprintln(os.Stderr)
			break
		}
	}
	return &pw
}

// Asks for password confirmation. Returns error if passwords don't match or a
// byte slice pointer if they do.
func AskAndConfirmPassword(prompt string, minimumLength int) (*[]byte, error) {
	var pwd1 *[]byte
	var pwd2 *[]byte
	for {
		pwd1 = AskForPassword(prompt, minimumLength)
		if pwd1 == nil {
			return nil, ErrPasswordInput
		}
		pwd2 = AskForPassword(prompt+RepeatPromptSuffix, 0)
		if pwd2 == nil {
			return nil, ErrPasswordInput
		}
		if bytes.Equal(*pwd1, *pwd2) {
			WipeBytes(pwd2)
			break
		}
		WipeBytes(pwd1)
		WipeBytes(pwd2)
		fmt.Println("Sorry, the keys you entered did not match. Try again.")
	}
	return pwd1, nil
}

// Generate a hex string compatible with WithSaltString() and
// SetSaltFromString(). The hex string is MinimumSaltLength*2 (default 64)
// characters long which can be decoded into a MinimumSaltLength byte long byte
// slice using hex.DecodeString(). The salt is not a secret and should be shared
// with whoever is supposed to decrypt a Krypto431 persistence file (when, for
// example, exporting keys, messages or even main persistence files). Function
// will panic if there is an error.
func GenerateSalt() string {
	salt := make([]byte, MinimumSaltLength)
	_, err := crand.Read(salt)
	if err != nil {
		panic(err)
	}
	return hex.EncodeToString(salt)
}

// Generate a random 32 byte persistence file key for use when loading/saving
// the persistence file. Returns a hex encoded string of 64 characters that you
// can use as e.g environment variable and is compatible with
// SetKeyFromString(). Beware that strings are immutable in Go - the internal
// wipe functions can not be used to clear this sensitive data. The default
// password-based method in Load() and Save() use byte or rune slices which are
// (or can be) wiped in an attempt not to leave sensitive data around in memory
// after the program exits. Function will panic if there is an error.
func GeneratePFK() string {
	key := make([]byte, 32)
	_, err := crand.Read(key)
	if err != nil {
		panic(err)
	}

	return hex.EncodeToString(key)
}

// Krypto431_Save persists a Krypto431 instance to file. The output file is a
// gzipped GOB (Go Binary) which is XSalsa20Poly1305 encrypted using a 32 byte
// key set via DeriveKeyFromPassword(), SetKeyFromString() or WithKey().
func (k *Krypto431) Save() error {
	k.mx.Lock()
	defer k.mx.Unlock()
	if len(k.persistence) == 0 {
		return ErrNoPersistence
	}
	// If persistence file starts with a tilde, resolve it to the user's home
	// directory.
	if strings.HasPrefix(k.persistence, "~/") {
		dirname, err := os.UserHomeDir()
		if err != nil {
			return err
		}
		k.persistence = filepath.Join(dirname, k.persistence[2:])
	}
	_, err := os.Stat(k.persistence)
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			// Other error than file not found...
			return err
		}
	} else {
		// persistence already exists
		if !k.overwritePersistenceIfExists {
			if k.interactive {
				overwrite := false
				prompt := &survey.Confirm{
					Message: fmt.Sprintf("Overwrite %s?", k.persistence),
				}
				err := survey.AskOne(prompt, &overwrite)
				if err != nil {
					return err
				}
				if !overwrite {
					return nil
				}
			} else {
				return fmt.Errorf("file %s already exist (will not overwrite)", k.persistence)
			}
		}
	}
	// Ask for password if instance key is empty and mode is interactive, fail otherwise.
	if k.persistenceKey == nil {
		if k.interactive {
			pwd, err := AskAndConfirmPassword(EncryptionPrompt, MinimumPasswordLength)
			if err != nil {
				return err
			}
			err = k.DeriveKeyFromPassword(pwd)
			if err != nil {
				return err
			}
		} else {
			return ErrNilPFK
		}
	}
	// Create persistence file if it does not exist or truncate it if it does exist.
	f, err := os.OpenFile(k.persistence, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	// Krypto431 persistence files are encrypted, gzipped GOB files.
	encrypter, err := stream.NewEncryptedStream(f, &stream.Config{
		Cipher:          stream.NewXSalsa20Poly1305Cipher((*[32]byte)(*k.persistenceKey)),
		SequentialNonce: false, // The key is the same and will leak if nonce is sequential.
		Initiator:       true,
	})
	if err != nil {
		return err
	}
	defer encrypter.Close()
	fgz := gzip.NewWriter(encrypter)
	defer fgz.Close()
	gobEncoder := gob.NewEncoder(fgz)
	err = gobEncoder.Encode(k)
	if err != nil {
		return err
	}
	return nil
}

// Krypto431_Load() loads a Krypto431 instance from the configured persistence
// file (k.persistence). Only exported fields will be populated.
func (k *Krypto431) Load() error {
	k.mx.Lock()
	defer k.mx.Unlock()
	if len(k.persistence) == 0 {
		return ErrNoPersistence
	}
	// If persistence file starts with a tilde, resolve it to the user's home
	// directory.
	if strings.HasPrefix(k.persistence, "~/") {
		dirname, err := os.UserHomeDir()
		if err != nil {
			return err
		}
		k.persistence = filepath.Join(dirname, k.persistence[2:])
	}

	var f *os.File
	_, err := os.Stat(k.persistence)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("persistence file %s does not exist, please initialize it to continue", k.persistence)
		}
		return err
	}

	// Persistence file exists, ask for password if instance key is empty.
	if k.persistenceKey == nil {
		if k.interactive {
			pwd := AskForPassword(DecryptionPrompt, MinimumPasswordLength)
			if pwd == nil {
				return ErrPasswordInput
			}
			err := k.DeriveKeyFromPassword(pwd)
			if err != nil {
				return err
			}
		} else {
			return ErrNilPFK
		}
	}
	// Load persisted data...
	f, err = os.Open(k.persistence)
	if err != nil {
		return err
	}
	defer f.Close()
	decrypter, err := stream.NewEncryptedStream(f, &stream.Config{
		Cipher:          stream.NewXSalsa20Poly1305Cipher((*[32]byte)(*k.persistenceKey)),
		SequentialNonce: false, // The key is the same and will leak if nonce is sequential.
		Initiator:       false,
	})
	if err != nil {
		return err
	}
	defer decrypter.Close()
	fgz, err := gzip.NewReader(decrypter)
	if err != nil {
		return err
	}
	defer fgz.Close()
	gobDecoder := gob.NewDecoder(fgz)
	err = gobDecoder.Decode(k)
	if err != nil {
		return err
	}
	// Fix all non-exported instance fields in keys and messages...
	for i := range k.Keys {
		k.Keys[i].instance = k
	}
	for i := range k.Messages {
		k.Messages[i].instance = k
	}
	// Allow overwriting file after it's been loaded...
	k.overwritePersistenceIfExists = true
	return nil
}

// Krypto431.ExportKeys() returns a new instance based on the current instance
// where only the keys that pass the filterFunction are copied over (entirely
// w/o messages). The filterFunction must return true for each key to to export
// (copy to the new instance) and false to not copy the key. The new instance's
// persistence field (filename of the save-file) will be empty unless option
// function WithPersistence(filename) is specified (can also be configured
// afterwards with SetPersistence()). Any Option function (With*) can be used to
// override any copied field.
func (k *Krypto431) ExportKeys(filterFunction func(key *Key) bool, opts ...Option) Krypto431 {
	n := Krypto431{
		persistenceKey:               BytePtr(ByteCopy(k.persistenceKey)),
		salt:                         BytePtr(ByteCopy(k.salt)),
		overwritePersistenceIfExists: false,
		interactive:                  k.interactive,
		GroupSize:                    k.GroupSize,
		KeyLength:                    k.KeyLength,
		Columns:                      k.Columns,
		KeyColumns:                   k.KeyColumns,
		Keys:                         make([]Key, 0, len(k.Keys)),
		Messages:                     make([]Message, 0, 0),
		CallSign:                     RuneCopy(&k.CallSign),
	}
	for _, opt := range opts {
		opt(&n)
	}
	if n.mx == nil {
		n.mx = &sync.Mutex{}
	}
	for i := range k.Keys {
		if filterFunction(&k.Keys[i]) {
			newKey := k.Keys[i]
			newKey.instance = &n
			n.Keys = append(n.Keys, newKey)
		}
	}
	return n
}

func (k *Krypto431) ImportKeys(filterFunction func(key *Key) bool, persistence)
