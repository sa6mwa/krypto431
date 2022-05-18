package krypto431

import (
	"fmt"
	"math"
	"runtime"

	"github.com/sa6mwa/krypto431/crand"
)

// ContainsKeyId checks if the Instance.Keys slice already contains Id and
// return true if it does, false if it does not.
func (r *Instance) ContainsKeyId(keyId *[]rune) bool {
	if keyId == nil {
		return false
	}
	for i := range r.Keys {
		if string(r.Keys[i].Id) == string(*keyId) {
			return true
		}
	}
	return false
}

// NewKey generates a new key. The current implementation generates a random
// group not in the Instance construct.
func (r *Instance) NewKey() *Key {
	key := Key{
		Id:        make([]rune, r.GroupSize),
		Runes:     make([]rune, int(int(math.Ceil(float64(r.KeyLength)/float64(r.GroupSize)))*r.GroupSize)),
		Used:      false,
		Decrypted: true,
		instance:  r,
	}
	for { // if we already have 26*26*26*26*26 keys, this is an infinite loop :)
		for i := range key.Id {
			key.Id[i] = rune(crand.Intn(26)) + rune('A')
		}
		if !r.ContainsKeyId(&key.Id) {
			break
		}
		// 2 next lines for debugging, will be removed
		_, fn, line, _ := runtime.Caller(1)
		fmt.Printf("key exists looping (%s line %d)\n", fn, line)
	}
	for i := range key.Runes {
		key.Runes[i] = rune(crand.Intn(26)) + rune('A')
	}
	return &key
}

// GenerateOneKey generates a single key and appends it to the Instance.Keys
// slice
func (r *Instance) GenerateOneKey() error {
	r.Keys = append(r.Keys, *r.NewKey())
	return nil
}

// GenerateKeys creates n amount of keys
func (r *Instance) GenerateKeys(n int) error {
	for i := 0; i < n; i++ {
		err := r.GenerateOneKey()
		if err != nil {
			return err
		}
	}
	return nil
}
