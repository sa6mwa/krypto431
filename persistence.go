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
	passwordvalidator "github.com/wagslane/go-password-validator"
	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/term"
)

const (
	errUnableToDerivePFK string = "unable to derive PFK from password: "
)

var (
	RepeatPromptSuffix  string = "(repeat) "
	EncryptionPrompt    string = "Enter encryption key: "
	DecryptionPrompt    string = "Enter decryption key: "
	NewEncryptionPrompt string = "Enter new encryption key: "
)

var (
	ErrNoSalt       = errors.New(errUnableToDerivePFK + "instance is missing salt")
	ErrTooShortSalt = errors.New(errUnableToDerivePFK + "salt is too short")
	//ErrPasswordTooShort = fmt.Errorf(errUnableToDerivePFK+"too short, must be at least %d characters long", MinimumPasswordLength)
	ErrNilPFK         = errors.New("instance is missing key needed to encrypt or decrypt persistence")
	ErrInvalidPFK     = errors.New("persistence file key is invalid, must be 32 bytes long")
	ErrPasswordInput  = errors.New("password input error")
	ErrCopyKeyFailure = errors.New("copy key failure")
)

// DerivePFKFromPassword uses PBKDF2 to produce the 32 byte long key used to
// encrypt/decrypt the persistence file. The salt in the Krypto431 instance is
// used to derive the key, either the default fixed salt or one that you
// provided earlier (e.g krypto431.New(krypto431.WithSalt(my64charHexString))).
func (k *Krypto431) DerivePFKFromPassword(password *[]byte) error {
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
	entropyBits := passwordvalidator.GetEntropy(string(*password))
	err := passwordvalidator.Validate(string(*password), MinimumPasswordEntropyBits)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Warning: %v (%.0f<%.0f)"+LineBreak, err, entropyBits, MinimumPasswordEntropyBits)
	}
	dk := pbkdf2.Key(*password, *k.salt, DefaultPBKDF2Iteration, 32, sha256.New)
	k.persistenceKey = &dk
	return nil
}

// Same as DerivePFKFromPassword, but validates the password against
// go-password-validator according to set minimum entropy bits.
func (k *Krypto431) DerivePFKFromPasswordWithValidation(password *[]byte) error {
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
	err := passwordvalidator.Validate(string(*password), MinimumPasswordEntropyBits)
	if err != nil {
		return err
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
func (k *Krypto431) SetPFKFromString(key string) error {
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

// Similar to SetPFKFromString() except it derives the key from a passphrase via
// the PBKDF2 function DerivePFKFromPassword. The instance's
// configured salt is used and need to be set before calling this function.
func (k *Krypto431) SetPFKFromPassword(password string) error {
	byteKey := []byte(password)
	err := k.DerivePFKFromPassword(&byteKey)
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

func AskAndConfirmPassword(prompt string, minimumEntropyBits float64) (*[]byte, error) {
	var pwd1 *[]byte
	var pwd2 *[]byte
	for {
		pwd1 = AskForPassword(prompt, 0)
		if pwd1 == nil {
			return nil, ErrPasswordInput
		}
		entropyBits := passwordvalidator.GetEntropy(string(*pwd1))
		err := passwordvalidator.Validate(string(*pwd1), minimumEntropyBits)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Denied: %v (%.0f<%.0f)"+LineBreak, err, entropyBits, MinimumPasswordEntropyBits)
			WipeBytes(pwd1)
			continue
		} else {
			fmt.Fprintf(os.Stderr, "OK: Password entropy is %.0f"+LineBreak, entropyBits)
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
		fmt.Fprintln(os.Stderr, "Sorry, the keys you entered did not match. Try again.")
	}
	return pwd1, nil
}

// Asks for password confirmation. Returns error if passwords don't match or a
// byte slice pointer if they do.
func OldAskAndConfirmPassword(prompt string, minimumLength int) (*[]byte, error) {
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
// SetPFKFromString(). Beware that strings are immutable in Go - the internal
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
// key set via DerivePFKFromPassword(), SetPFKFromString() or WithPFK().
func (k *Krypto431) Save() error {
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
			pwd, err := AskAndConfirmPassword(EncryptionPrompt, MinimumPasswordEntropyBits)
			if err != nil {
				return err
			}
			err = k.DerivePFKFromPassword(pwd)
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
			pwd := AskForPassword(DecryptionPrompt, 0)
			if pwd == nil {
				return ErrPasswordInput
			}
			err := k.DerivePFKFromPassword(pwd)
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
		persistenceKey:                BytePtr(ByteCopy(k.persistenceKey)),
		salt:                          BytePtr(ByteCopy(k.salt)),
		overwritePersistenceIfExists:  false,
		interactive:                   k.interactive,
		overwriteExistingKeysOnImport: false,
		GroupSize:                     k.GroupSize,
		KeyLength:                     k.KeyLength,
		Columns:                       k.Columns,
		KeyColumns:                    k.KeyColumns,
		Keys:                          make([]Key, 0, len(k.Keys)),
		Messages:                      make([]Message, 0),
		CallSign:                      RuneCopy(&k.CallSign),
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

// Krypto431_ImportKeys() does the opposite of ExportKeys(). The filterFunction
// runs on each key from the persistence file specified in the opts variadic
// WithPersistence(filename), for example:
//
//	ImportKeys(myFilter, krypto431.WithPersistence(filename), krypto431.WithInteractive(true))
//
// The default salt is used when loading the file and the PFK is empty. Load()
// will interactively ask for password only if WithInteractive(true) is provided
// as an option or it will return an error. To override PFK and/or salt, use
// WithPFK() or WithPFKString(), WithSalt() or WithSaltString(). To use the key
// and salt from the current instance for the imported instance, you can do the
// following:
//
//	k.ImportKeys(f, WithPersistence(file), WithPFK(k.GetPFK()), WithSalt(k.GetSalt()))
//
// If an imported key ID already exists in the receiving instance and
// interactive mode is enabled, function will ask for confirmation before
// overwriting. To force overwriting without asking, add
// WithOverwriteExistingKeysOnImport(true).
func (k *Krypto431) ImportKeys(filterFunction func(key *Key) bool, opts ...Option) (int, error) {
	keyCount := 0
	incoming := New(opts...)
	fmt.Fprintf(os.Stderr, "Importing keys from %s"+LineBreak, incoming.GetPersistence())

	err := incoming.Load()
	if err != nil {
		return 0, err
	}
	defer incoming.Wipe()
	for i := range incoming.Keys {
		if len(incoming.Keys[i].Id) != k.GroupSize {
			fmt.Fprintf(os.Stderr, "Key ID %s is not %d characters long (our group size), will not import.", string(incoming.Keys[i].Id), k.GroupSize)
			continue
		}
		if filterFunction(&incoming.Keys[i]) {
			if k.ContainsKeyId(&incoming.Keys[i].Id) {
				if !k.overwriteExistingKeysOnImport && k.interactive {
					overwrite := false
					prompt := &survey.Confirm{
						Message: fmt.Sprintf("Key ID %s already exist, replace with imported key?", string(incoming.Keys[i].Id)),
					}
					err := survey.AskOne(prompt, &overwrite)
					if err != nil {
						return keyCount, err
					}
					if !overwrite {
						continue
					}
				} else if !k.overwriteExistingKeysOnImport {
					fmt.Fprintf(os.Stderr, "Key ID %s already exist, will not import.", string(incoming.Keys[i].Id))
					continue
				}
				err := k.DeleteKey(incoming.Keys[i].Id)
				if err != nil {
					return keyCount, err
				}
			}
			// As the incoming key is wiped, copy rune slices to new key...
			var newKey Key
			newKey.Id = make([]rune, len(incoming.Keys[i].Id))
			if copy(newKey.Id, incoming.Keys[i].Id) != len(incoming.Keys[i].Id) {
				return keyCount, ErrCopyKeyFailure
			}
			newKey.Runes = make([]rune, len(incoming.Keys[i].Runes))
			if copy(newKey.Runes, incoming.Keys[i].Runes) != len(incoming.Keys[i].Runes) {
				return keyCount, ErrCopyKeyFailure
			}
			for _, z := range incoming.Keys[i].Keepers {
				c := make([]rune, len(z))
				if copy(c, z) != len(z) {
					return keyCount, ErrCopyKeyFailure
				}
				newKey.Keepers = append(newKey.Keepers, c)
			}
			newKey.Created = incoming.Keys[i].Created
			newKey.Expires = incoming.Keys[i].Expires
			newKey.Used = incoming.Keys[i].Used
			newKey.Compromised = incoming.Keys[i].Compromised
			newKey.Comment = make([]rune, len(incoming.Keys[i].Comment))
			if copy(newKey.Comment, incoming.Keys[i].Comment) != len(incoming.Keys[i].Comment) {
				return keyCount, ErrCopyKeyFailure
			}
			newKey.instance = k
			// Remove my call-sign from keepers, add incoming station's call-sign to
			// keepers and hand over key to our instance (importedKey.instance = k).
			newKey.RemoveKeeper(k.CallSign).AddKeeper(incoming.Keys[i].GetCallSign()).
				SetInstance(k)
			k.Keys = append(k.Keys, newKey)
			keyCount++
		}
	}

	return keyCount, nil
}
