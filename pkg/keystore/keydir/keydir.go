package keydir

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/sa6mwa/krypto431/pkg/keystore"
	"github.com/sa6mwa/krypto431/pkg/krand"
)

type KeyDir struct {
	io.Reader
	dir     string
	keys    []*Key
	openKey *Key
}

const keyExt = ".key"

// New creates a new KeyDir keystore
func New(dir string) *KeyDir {
	c := KeyDir{
		dir: dir,
	}
	return &c
}

// Open opens a directory with keys
func (k *KeyDir) Open() error {
	stat, err := os.Stat(k.dir)
	if err != nil {
		return fmt.Errorf("error locating directory: %w", err)
	}
	if !stat.IsDir() {
		return fmt.Errorf("not a directory")
	}

	err = k.reloadKeyDir()
	if err != nil {
		return fmt.Errorf("error loading available keys: %w", err)
	}

	return nil
}

// Close closes the directory and saves any unsaved state
func (k *KeyDir) Close() error {
	if k.openKey != nil {
		k.openKey.close()
		k.openKey = nil
	}
	k.keys = nil
	return nil
}

// NextKey changes the current key to the next key in the list (sorted by name)
// The key offset is always reset to 0
func (k *KeyDir) NextKey() (keystore.Key, error) {
	if len(k.keys) == 0 {
		return nil, keystore.ErrNoMoreKeys
	}
	key := k.keys[0]
	k.keys = k.keys[1:]
	err := k.loadKey(key)
	if err != nil {
		return nil, fmt.Errorf("error loading key '%s': %w", key.name, err)
	}
	return key, nil
}

// OpenKey changes the current key to a named key in the list
func (k *KeyDir) OpenKey(name string) (keystore.Key, error) {
	err := k.reloadKeyDir()
	if err != nil {
		return nil, fmt.Errorf("error loading available keys: %w", err)
	}

	idxFound := -1
	for i, key := range k.keys {
		if key.name == name {
			idxFound = i
			break
		}
	}
	if idxFound < 0 {
		return nil, keystore.ErrKeyNotFound
	}
	key := k.keys[idxFound]
	err = k.loadKey(key)
	if err != nil {
		return nil, fmt.Errorf("error loading key '%s': %w", name, err)
	}
	return key, nil
}

// Generate generates a new named key in the directory
// rng is a random number source to read size bytes from
func (k *KeyDir) Generate(name string, size int64, rng io.Reader) error {
	fPath := filepath.Join(k.dir, name+keyExt)
	_, err := os.Stat(fPath)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("stat error: %w", err)
	} else if err == nil {
		return os.ErrExist
	}
	f, err := os.Create(fPath)
	if err != nil {
		return fmt.Errorf("error creating key file '%s': %w", fPath, err)
	}
	defer f.Close()
	_, err = krand.Generate(rng, f, size)
	if err != nil {
		return fmt.Errorf("error generating key: %w", err)
	}
	err = f.Close()
	if err != nil {
		return fmt.Errorf("error closing file '%s': %w", fPath, err)
	}
	return nil
}

func (k *KeyDir) reloadKeyDir() error {
	k.keys = nil
	dirItems, err := os.ReadDir(k.dir)
	if err != nil {
		return fmt.Errorf("error reading directory items in '%s': %w", k.dir, err)
	}
	for _, item := range dirItems {
		if !item.Type().IsRegular() {
			continue
		}
		fn := filepath.Join(k.dir, item.Name())
		stat, err := os.Stat(fn)
		if err != nil {
			return fmt.Errorf("stat error: %w", err)
		}
		if filepath.Ext(item.Name()) == keyExt {
			k.keys = append(k.keys, &Key{
				dir:  k.dir,
				name: strings.TrimSuffix(item.Name(), keyExt),
				len:  stat.Size(),
			})
		}
	}
	sort.SliceStable(k.keys, func(i, j int) bool {
		ni := k.keys[i].name
		nj := k.keys[j].name
		if ni == nj {
			return false
		}
		niNs := newNatStr(ni)
		njNs := newNatStr(nj)
		return natLess(niNs, njNs)
	})

	return nil
}

func (k *KeyDir) loadKey(key *Key) error {
	var err error
	if k.openKey != nil {
		_ = k.openKey.close()
		k.openKey = nil
	}
	err = key.open()
	if err != nil {
		return err
	}
	k.openKey = key
	return nil
}
