package krypto431

import (
	"fmt"
	"math"
	"os"
	"strings"
	"time"

	"github.com/sa6mwa/krypto431/crand"
)

// ContainsKeyId checks if the Krypto431.Keys slice already contains Id and
// return true if it does, false if it does not.
func (k *Krypto431) ContainsKeyId(keyId *[]rune) bool {
	if keyId == nil {
		return false
	}
	for i := range k.Keys {
		if EqualRunesFold(&k.Keys[i].Id, keyId) {
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
		Id:          make([]rune, k.GroupSize),
		Runes:       make([]rune, int(int(math.Ceil(float64(k.KeyLength)/float64(k.GroupSize)))*k.GroupSize)),
		Used:        false,
		Compromised: false,
		instance:    k,
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

func (k *Krypto431) DeleteKey(keyIds ...string) error {
	k.mx.Lock()
	defer k.mx.Unlock()
	if len(keyIds) == 0 {
		return nil
	}
	var vettedKeyIds [][]rune
	defer func() {
		for i := range vettedKeyIds {
			fmt.Println("Deleting " + string(vettedKeyIds[i]))
			Wipe(&vettedKeyIds[i])
		}
		vettedKeyIds = nil
	}()
	for i := range keyIds {
		keyId := []rune(strings.TrimSpace(strings.ToUpper(keyIds[i])))
		if len(keyId) != k.GroupSize {
			return fmt.Errorf("\"%s\" is not the length of the configured group size (%d)", string(keyId), k.GroupSize)
		}
		vettedKeyIds = append(vettedKeyIds, keyId)
	}
	for x := range vettedKeyIds {
		for i := range k.Keys {
			if EqualRunes(&k.Keys[i].Id, &vettedKeyIds[x]) {
				k.Keys[i].Wipe()
				k.Keys[i] = k.Keys[len(k.Keys)-1]
				k.Keys = k.Keys[:len(k.Keys)-1]
				break
			}
		}
	}
	return nil
}

func (k *Krypto431) DeleteKeysFromSummaryString(summaryStrings ...string) error {
	for i := range summaryStrings {
		key, _, _ := strings.Cut(summaryStrings[i], " ")
		err := k.DeleteKey(key)
		if err != nil {
			return err
		}
	}
	return nil
}

// GenerateKeys creates n amount of keys.
func (k *Krypto431) GenerateKeys(n int, keepers ...string) error {
	k.mx.Lock()
	defer k.mx.Unlock()
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
// Krypto431.KeyColumns (e.g DefaultKeyColumns). Don't forget to Wipe(b []rune)
// this slice when you are done!
func (k *Key) GroupsBlock() (*[]rune, error) {
	return groups(&k.Runes, k.instance.GroupSize, k.instance.KeyColumns)
}

func (k *Key) JoinKeepers(separator string) string {
	return JoinRunesToString(&k.Keepers, separator)
}

// Check if key is still valid or has expired, returns true if still valid,
// false if not.
func (k *Key) IsExpired() bool {
	return time.Now().After(k.Expires.Time)
}

// Check if key is valid at least one day before expiring. Returns true if key
// is OK, false if not.
func (k *Key) IsValidOneDay() bool {
	return k.IsValid(-24 * time.Hour)
}

// Check if key is valid d amount of time before expiring (e.g 24*time.Hour for
// one day). Returns true if key does not expire within d time or false if it
// does.
func (k *Key) IsValid(d time.Duration) bool {
	return time.Now().Add(-d).After(k.Expires.Time)
}

// Returns Yes if key is marked used, No if not.
func (k *Key) UsedString() string {
	if k.Used {
		return "Yes"
	}
	return "No"
}

// Returns Yes if key is marked compromised, No if not.
func (k *Key) CompromisedString() string {
	if k.Compromised {
		return "Yes"
	}
	return "No"
}

// continue here TODO
// add sort function to list (for list, delete, etc).
// idea: let digest be pointer slice with keys, sort pointers based on date, etc...
//
//	sort.Slice(dateSlice, func(i, j int) bool {
//			return dateSlice[i].sortByThis.Before(dateSlice[j].sortByThis)
//		})
func (k *Krypto431) SummaryOfKeys(filterFunction func(key *Key) bool) (header []rune, lines [][]rune) {
	var digests [][][]rune
	defer func() {
		for a := range digests {
			for i := range digests[a] {
				Wipe(&digests[a][i])
			}
			digests[a] = nil
		}
		digests = nil
	}()
	for i := range k.Keys {
		if filterFunction(&k.Keys[i]) {
			digests = append(digests, k.Keys[i].Digest())
		}
	}
	if len(digests) > 0 {
		columnHeader := []string{"ID", "KEEPERS", "CREATED", "EXPIRES", "USED", "COMPROMISED", "COMMENT"}
		columnSizes := ColumnSizes(columnHeader, digests)
		if len(columnSizes) != len(columnHeader) {
			panic("wrong number of columns")
		}
		// Generate formatted header rune slice...
		for i := range columnSizes {
			if len(columnHeader) <= i {
				continue
			}
			header = append(header, []rune(columnHeader[i])...)
			if i < len(columnSizes)-1 {
				padding := columnSizes[i] - len(columnHeader[i]) + 1
				for x := 0; x < padding; x++ {
					header = append(header, rune(' '))
				}
			}
		}
		// Populate lines with keys...
		for row := range digests {
			var line []rune
			for col := range digests[row] {
				if col >= len(columnSizes) {
					continue
				}
				line = append(line, digests[row][col]...)
				if col < len(digests[row])-1 {
					padding := columnSizes[col] - len(digests[row][col]) + 1
					for x := 0; x < padding; x++ {
						line = append(line, rune(' '))
					}
				}
			}
			if len(line) > 0 {
				lines = append(lines, line)
			} else {
				panic("empty line")
			}
		}
	}
	return
}

// Digest returns a slice of strings-as-rune-slices describing the key. Items in
// the slice are ID, KEEPERS, CREATED, EXPIRES, USED (Y/N), COMPROMISED (Y/N),
// COMMENT. The rune slices can be cleared with Wipe().
func (k *Key) Digest() (digest [][]rune) {
	digest = append(digest, RuneCopy(&k.Id))
	if len(k.Keepers) > 0 {
		digest = append(digest, []rune(k.JoinKeepers(",")))
	} else {
		digest = append(digest, []rune("Anonymous"))
	}
	digest = append(digest, []rune(k.Created.String()))
	digest = append(digest, []rune(k.Expires.String()))
	digest = append(digest, []rune(k.UsedString()))
	digest = append(digest, []rune(k.CompromisedString()))
	digest = append(digest, RuneCopy(&k.Comment))
	return
}
