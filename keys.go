package krypto431

import (
	"fmt"
	"math"
	"os"

	"github.com/sa6mwa/krypto431/crand"
)

// ContainsKeyId checks if the Krypto431.Keys slice already contains Id and
// return true if it does, false if it does not.
func (k *Krypto431) ContainsKeyId(keyId *[]rune) bool {
	if keyId == nil {
		return false
	}
	for i := range k.Keys {
		if string(k.Keys[i].Id) == string(*keyId) {
			return true
		}
	}
	return false
}

// NewKey generates a new key. The current implementation generates a random
// group not yet in the Krypto431 construct. Keepers can be one call-sign per
// variadic, comma-separated call-signs or a combination of both.
func (k *Krypto431) NewKey(keepers ...string) *[]rune {
	key := Key{
		Id:       make([]rune, k.GroupSize),
		Runes:    make([]rune, int(int(math.Ceil(float64(k.KeyLength)/float64(k.GroupSize)))*k.GroupSize)),
		Used:     false,
		instance: k,
	}

	key.Keepers = VettedKeepers(keepers...)

	for { // if we already have 26*26*26*26*26 keys, this is an infinite loop :)
		for i := range key.Id {
			key.Id[i] = rune(crand.Intn(26)) + rune('A')
		}
		if !k.ContainsKeyId(&key.Id) {
			break
		}
		fmt.Fprintf(os.Stderr, "Key %s already exist, retrying..."+LineBreak, string(key.Id))
		/*
			 		// 2 next lines for debugging, will be removed
					_, fn, line, _ := runtime.Caller(1)
					fmt.Printf("key exists looping (%s line %d)\n", fn, line)
		*/
	}
	for i := range key.Runes {
		key.Runes[i] = rune(crand.Intn(26)) + rune('A')
	}
	k.Keys = append(k.Keys, key)
	return &key.Id
}

// GenerateKeys creates n amount of keys
func (k *Krypto431) GenerateKeys(n int, keepers ...string) error {
	for i := 0; i < n; i++ {
		_ = k.NewKey(keepers...)
	}
	return nil
}

// KeyLength() returns the length of this key instance.
func (k *Key) KeyLength() int {
	return len(k.Runes)
}

// Groups for keys return a rune slice where each number of GroupSize runes are
// separated by a space. Don't forget to Wipe() this slice when you are done!
func (k *Key) Groups() (*[]rune, error) {
	return groups(&k.Runes, k.instance.GroupSize, 0)
}

// GroupsBlock returns a string-as-rune-slice representation of the key where
// each group is separated by a space or new line if a line becomes longer than
// Krypto431.Columns (or DefaultColumns). Don't forget to Wipe(b []rune) this
// slice when you are done!
func (k *Key) GroupsBlock() (*[]rune, error) {
	return groups(&k.Runes, k.instance.GroupSize, k.instance.KeyColumns)
}
