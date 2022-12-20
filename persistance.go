package krypto431

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/gob"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/AlecAivazis/survey/v2"
	stream "github.com/nknorg/encrypted-stream"
	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/term"
)

const (
	passwordPrompt       string = "Enter encryption key: "
	repeatPasswordPrompt string = passwordPrompt + "(repeat) "
	errUnableToDeriveKey string = "unable to derive key from password: "
	errUnableToSave      string = "unable to save instance: "
	errUnableToLoad      string = "unable to load instance: "
)

var (
	ErrNoSalt           = errors.New(errUnableToDeriveKey + "krypto431 instance is missing salt")
	ErrTooShortSalt     = errors.New(errUnableToDeriveKey + "instance salt is too short")
	ErrPasswordTooShort = fmt.Errorf(errUnableToDeriveKey+"password too short, must be at least %d characters long", MinimumPasswordLength)
	ErrNilKey           = errors.New("instance is missing key needed to encrypt or decrypt the save file")
	ErrPasswordInput    = errors.New("password input error")
)

// DeriveKeyFromPassword uses PBKDF2 to produce the 32 byte long key used to
// encrypt/decrypt the persistance save file. The salt in the Krypto431 instance
// is used to derive the key, either the default fixed salt or one that you
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
	dk := pbkdf2.Key(*password, *k.salt, 4096, 32, sha256.New)
	k.saveFileKey = &dk
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
		for _ = range ch {
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

// https://pkg.go.dev/golang.org/x/crypto/pbkdf2
//
// https://github.com/nknorg/encrypted-stream

// Krypto431_Save persists a Krypto431 instance to a file. The output file is a gzipped GOB (Go Binary) which is XSalsa20Poly1305 encrypted using a
func (k *Krypto431) Save() error {
	if len(k.saveFile) == 0 {
		return ErrNoSaveFile
	}
	// If save file starts with a tilde, resolve it to the user's home directory.
	if strings.HasPrefix(k.saveFile, "~/") {
		dirname, err := os.UserHomeDir()
		if err != nil {
			return err
		}
		k.saveFile = filepath.Join(dirname, k.saveFile[2:])
	}
	_, err := os.Stat(k.saveFile)
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			// Other error than file not found...
			return err
		}
	} else {
		// saveFile already exists
		if !k.overwriteSaveFileIfExists {
			if k.interactive {
				overwrite := false
				prompt := &survey.Confirm{
					Message: fmt.Sprintf("Overwrite %s?", k.saveFile),
				}
				err := survey.AskOne(prompt, &overwrite)
				if err != nil {
					return err
				}
				if !overwrite {
					return nil
				}
			} else {
				return fmt.Errorf("save file %s already exist (will not overwrite)", k.saveFile)
			}
		}
	}
	// Ask for password if instance key is empty.
	if k.saveFileKey == nil {
		if k.interactive {
			var pwd1 *[]byte
			var pwd2 *[]byte
			for {
				pwd1 = AskForPassword(passwordPrompt, MinimumPasswordLength)
				if pwd1 == nil {
					return fmt.Errorf(errUnableToLoad+"%w", ErrPasswordInput)
				}
				pwd2 = AskForPassword(repeatPasswordPrompt, 0)
				if pwd2 == nil {
					return fmt.Errorf(errUnableToLoad+"%w", ErrPasswordInput)
				}
				if bytes.Compare(*pwd1, *pwd2) == 0 {
					WipeBytes(pwd2)
					break
				}
				WipeBytes(pwd1)
				WipeBytes(pwd2)
				fmt.Println("Sorry, the keys you entered did not match, try again.")
			}
			err := k.DeriveKeyFromPassword(pwd1)
			if err != nil {
				return fmt.Errorf(errUnableToSave+"key derivation failure: %w", err)
			}
		} else {
			return ErrNilKey
		}
	}
	// Create save file if it does not exist or truncate it if it does exist.
	f, err := os.OpenFile(k.saveFile, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	// Krypto431 save files are encrypted, gzipped GOB files.
	encrypter, err := stream.NewEncryptedStream(f, &stream.Config{
		Cipher:          stream.NewXSalsa20Poly1305Cipher((*[32]byte)(*k.saveFileKey)),
		SequentialNonce: true,
		Initiator:       true,
	})
	if err != nil {
		return fmt.Errorf(errUnableToSave+"encryption failure: %w", err)
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

func (k *Krypto431) Load() error {
	if len(k.saveFile) == 0 {
		return ErrNoSaveFile
	}
	// If save file starts with a tilde, resolve it to the user's home directory.
	if strings.HasPrefix(k.saveFile, "~/") {
		dirname, err := os.UserHomeDir()
		if err != nil {
			return err
		}
		k.saveFile = filepath.Join(dirname, k.saveFile[2:])
	}

	var f *os.File
	_, err := os.Stat(k.saveFile)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("persistance file %s does not exist, please initialize it to continue", k.saveFile)
		}
		return err
	}

	// Save file exists, ask for password if instance key is empty.
	if k.saveFileKey == nil {
		if k.interactive {
			pwd := AskForPassword(passwordPrompt, MinimumPasswordLength)
			if pwd == nil {
				return fmt.Errorf(errUnableToLoad+"%w", ErrPasswordInput)
			}
			err := k.DeriveKeyFromPassword(pwd)
			if err != nil {
				return fmt.Errorf(errUnableToLoad+"%w", err)
			}
		} else {
			return ErrNilKey
		}
	}

	// Load save file...
	f, err = os.Open(k.saveFile)
	if err != nil {
		return err
	}
	defer f.Close()
	decrypter, err := stream.NewEncryptedStream(f, &stream.Config{
		Cipher:          stream.NewXSalsa20Poly1305Cipher((*[32]byte)(*k.saveFileKey)),
		SequentialNonce: true,
		Initiator:       false,
	})
	if err != nil {
		return fmt.Errorf(errUnableToLoad+"decryption failure: %w", err)
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
	k.overwriteSaveFileIfExists = true
	return nil
}
