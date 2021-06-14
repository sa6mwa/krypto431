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

// GenerateKeyId generates an Id. The current implementation simply generates a
// random group not in the Instance construct.
func (r *Instance) GenerateKeyId(key *Key) error {
	key.Id = make([]rune, r.GroupSize)
	for { // if we already have 26*26*26*26*26 keys, this is an infinite loop :)
		for i := range key.Id {
			key.Id[i] = rune(crand.Intn(26)) + rune('A')
		}
		if !r.ContainsKeyId(key.Id) {
			break
		}
		// 2 next lines for debugging, will be removed
		_, fn, line := runtime.Caller(1)
		fmt.Printf("key exists looping (%s line %d)\n", fn, line)
	}
	return nil
}

// GenerateOneKey generates a single key and appends it to the Instance.Keys
// slice returning a pointer to the Key object
func (r *Instance) GenerateOneKey() error {
	// define a temporary key
	var key Key
	key.instance = r
	groupsToGenerate := int(math.Ceil(float64(r.KeyLength) / float64(r.GroupSize)))
	err := r.GenerateKeyId(&key)
	if err != nil {
		return nil, err
	}
	key.Runes = make([]rune, int(groupsToGenerate*r.GroupSize))
	for i := range key.Runes {
		key.Runes[i] = rune(crand.Intn(26)) + rune('A')
	}
	// append will copy key to the Keys slice
	r.Keys = append(r.Keys, key)
	// wipe the temporary key
	key.Wipe()
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
