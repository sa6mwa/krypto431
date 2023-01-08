package krypto431

import (
	"fmt"
	"math"
	"os"
	"strings"
	"time"

	"github.com/sa6mwa/dtg"
	"github.com/sa6mwa/krypto431/crand"
)

func (k Key) GoString() string {
	return fmt.Sprintf("Key{Id:%s Runes:\"%s\" Keepers:[%s] Created:%s Expires:%s Used:%t Compromised:%t Comment:\"%s\" instance:%p}",
		k.IdString(), string(k.Runes), k.JoinKeepers(","), k.Created, k.Expires, k.Used, k.Compromised, k.CommentString(), k.instance)
}

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

func (k *Key) ContainsKeeper(keepers ...[]rune) bool {
	if len(keepers) == 0 {
		return len(k.Keepers) == 0
	}
	if AllNeedlesInHaystack(&keepers, &k.Keepers, true) {
		return true
	}
	return false
}

// NewKey generates a new key. The current implementation generates a random
// group not yet in the Krypto431 construct. Keepers can be one call-sign per
// variadic, comma-separated call-signs or a combination of both.
func (k *Krypto431) NewKey(expire time.Time, keepers ...string) *Key {
	key := Key{
		Id:          make([]rune, k.GroupSize),
		Runes:       make([]rune, int(int(math.Ceil(float64(k.KeyLength)/float64(k.GroupSize)))*k.GroupSize)),
		Used:        false,
		Compromised: false,
		instance:    k,
	}
	key.Created.Time = time.Now()
	key.Expires.Time = expire
	key.Keepers = VettedKeepers(keepers...)
	// If the instance's call-sign is among the keepers, remove it.
	key.RemoveKeeper(k.CallSign)
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
	return &key
}

// DeleteKey removes one or more keys from the instance's Keys slice wiping the
// key before deleting it. Returns number of keys deleted or error on failure.
func (k *Krypto431) DeleteKey(keyIds ...[]rune) (int, error) {
	// TODO: error-handling is a future improvement.
	deleted := 0
	if len(keyIds) == 0 {
		return 0, nil
	}
	for x := range keyIds {
		for i := range k.Keys {
			if EqualRunesFold(&k.Keys[i].Id, &keyIds[x]) {
				k.Keys[i].Wipe()
				k.Keys[i] = k.Keys[len(k.Keys)-1]
				k.Keys = k.Keys[:len(k.Keys)-1]
				deleted++
				break
			}
		}
	}
	return deleted, nil
}

// DeleteKeyByString is an alias for DeleteKey where key IDs are issued as
// strings instead of rune slices.
func (k *Krypto431) DeleteKeyByString(keyIds ...string) (int, error) {
	return k.DeleteKey(VettedKeys(keyIds...)...)
}

func (k *Krypto431) DeleteKeysBySummaryString(summaryStrings ...string) (int, error) {
	deleted := 0
	for i := range summaryStrings {
		key, _, _ := strings.Cut(summaryStrings[i], " ")
		n, err := k.DeleteKeyByString(key)
		if err != nil {
			return deleted, err
		}
		deleted += n
	}
	return deleted, nil
}

// GenerateKeys creates n amount of keys. The expire argument is a Date-Time
// Group when the key(s) is/are to expire (DDHHMMZmmmYY). If expire is nil, keys
// will expire one year from current time. If no keepers are provided, keys will
// be considered anonymous.
func (k *Krypto431) GenerateKeys(n int, expire *string, keepers ...string) error {
	var expiryTime time.Time
	if expire == nil {
		expiryTime = time.Now().Add(365 * 24 * time.Hour)
	} else {
		d, err := dtg.Parse(*expire)
		if err != nil {
			return err
		}
		expiryTime = d.Time
	}
	for i := 0; i < n; i++ {
		k.NewKey(expiryTime, keepers...)
	}
	return nil
}

// AddKeeper adds keeper(s) to the Keepers slice if not already there. Can be
// chained.
func (k *Key) AddKeeper(keepers ...[]rune) *Key {
	for _, keeper := range keepers {
		if !k.ContainsKeeper(keeper) {
			k.Keepers = append(k.Keepers, keeper)
		}
	}
	return k
}

// RemoveKeeper removes keeper(s) from the Keepers slice if found. Can be
// chained.
func (k *Key) RemoveKeeper(keepers ...[]rune) *Key {
	for _, keeper := range keepers {
		for i := range k.Keepers {
			if EqualRunesFold(&keeper, &k.Keepers[i]) {
				k.Keepers[i] = k.Keepers[len(k.Keepers)-1]
				k.Keepers = k.Keepers[:len(k.Keepers)-1]
				break
			}
		}
	}
	return k
}

// Return the Krypto431 instance (non-exported field) of a key.
func (k *Key) GetInstance() *Krypto431 {
	return k.instance
}

// Set instance of Krypto431 (non-exported field) for a key. Can be chained.
func (k *Key) SetInstance(instance *Krypto431) *Key {
	k.instance = instance
	return k
}

func (k *Key) GetCallSign() []rune {
	return k.instance.CallSign
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
// does not expire within that time, false if not.
func (k *Key) IsValidOneDay() bool {
	return k.IsValid(24 * time.Hour)
}

// Check if key is valid at least 30 days before expiring. Returns true if key
// does not expire within that time, false if not.
func (k *Key) IsValidOneMonth() bool {
	return k.IsValid(30 * 24 * time.Hour)
}

// Check if key is valid at least one year (365 days) before expiring. Returns
// true if key does not expire within that time, false if not.
func (k *Key) IsValidOneYear() bool {
	return k.IsValid(365 * 24 * time.Hour)
}

// Check if key is valid d amount of time before expiring (e.g 24*time.Hour for
// one day). Returns true if key does not expire within d time or false if it
// does.
func (k *Key) IsValid(d time.Duration) bool {
	return time.Now().Add(d).Before(k.Expires.Time)
}

// Returns Yes if key is marked used, No if not. Optional rightSpacing pads the
// output string with trailing spaces.
func (k *Key) UsedString(rightSpacing ...int) string {
	if k.Used {
		return Words["Yes"]
	}
	return Words["No"]
}

// Returns string used if key is marked used or string notUsed if not marked
// used.
func (k *Key) UsedOrNotString(used string, notUsed string) string {
	if k.Used {
		return used
	}
	return notUsed
}

// Returns Yes if key is marked compromised, No if not.
func (k *Key) CompromisedString() string {
	if k.Compromised {
		return Words["Yes"]
	}
	return Words["No"]
}

func (k *Key) IdString() string {
	return string(k.Id)
}

func (k *Key) CommentString() string {
	return string(k.Comment)
}

// continue here TODO
// add sort function to list (for list, delete, etc).
// idea: let digest be pointer slice with keys, sort pointers based on date, etc...
//
//	sort.Slice(dateSlice, func(i, j int) bool {
//			return dateSlice[i].sortByThis.Before(dateSlice[j].sortByThis)
//		})
func (k *Krypto431) SummaryOfKeys(filter func(key *Key) bool) (header []rune, lines [][]rune) {
	var kp []*Key
	for i := range k.Keys {
		if filter(&k.Keys[i]) {
			kp = append(kp, &k.Keys[i])
		}
	}

	// TODO: sort kptrs here

	predictedColumnSizes := predictColumnSizesOfKeys(kp)

	columnHeader := []string{"ID", "KEEPERS", "CREATED", "EXPIRES", "USED", "COMPROMISED", "COMMENT"}
	// Guard rail...
	if len(predictedColumnSizes) != len(columnHeader) {
		panic("wrong number of columns")
	}
	addSpace := 1
	// Generate formatted header rune slice...
	for i := range predictedColumnSizes {
		if len(columnHeader) <= i {
			continue
		}
		// Add column header and padding.
		header = append(header, []rune(columnHeader[i])...)
		if i < len(predictedColumnSizes)-1 {
			padding := predictedColumnSizes[i] - len(columnHeader[i]) + addSpace
			for x := 0; x < padding; x++ {
				header = append(header, rune(' '))
			}
		}
	}
	// Populate lines rune slice with keys
	for i := range kp {
		var columns [][]rune
		columns = append(columns, withPadding(RuneCopy(&kp[i].Id), predictedColumnSizes[0]+addSpace))
		if len(kp[i].Keepers) > 0 {
			columns = append(columns, withPadding([]rune(kp[i].JoinKeepers(",")), predictedColumnSizes[1]+addSpace))
		} else {
			columns = append(columns, withPadding([]rune("Anonymous"), predictedColumnSizes[1]+addSpace))
		}
		columns = append(columns,
			withPadding([]rune(kp[i].Created.String()), predictedColumnSizes[2]+addSpace),
			withPadding([]rune(kp[i].Expires.String()), predictedColumnSizes[3]+addSpace),
			withPadding([]rune(kp[i].UsedString()), predictedColumnSizes[4]+addSpace),
			withPadding([]rune(kp[i].CompromisedString()), predictedColumnSizes[5]+addSpace),
			withPadding([]rune(kp[i].Comment), predictedColumnSizes[6]+addSpace))
		var totalLineLength int
		for x := range columns {
			totalLineLength += len(columns[x])
		}
		line := make([]rune, totalLineLength)
		var y int
		for z := range columns {
			y += copy(line[y:], columns[z])
		}
		lines = append(lines, line)
	}
	return
}
