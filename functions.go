package krypto431

import (
	"errors"
	"math"
	"regexp"
	"strings"
	"unicode"
)

// Functions not assigned to methods of more general use likely end up here.

func TrimRightRuneFunc(s []rune, f func(rune) bool) []rune {
	for i := len(s); i > 0; i-- {
		if f(s[i-1]) {
			s = s[:i-1]
		} else {
			break
		}
	}
	return s
}

// Configure go-password-validator minimum entropy for the entire krypto431
// package. Entropy limit is not instance-scoped (yet).
func SetMinimumPasswordEntropyBits(entropy float64) {
	MinimumPasswordEntropyBits = entropy
}

// Returns a rune slice where each group is separated by a space. If columns is
// above 0 the function will insert a line break instead of a space before
// extending beyond that column length. Don't forget to Wipe(myRuneSlice) when
// you are done!
func groups(input *[]rune, groupsize int, columns int) (*[]rune, error) {
	if input == nil {
		return nil, ErrNilPointer
	}
	if groupsize <= 0 {
		return nil, errors.New("groupsize must be above 0")
	}
	output := make([]rune, 0, int(math.Ceil(float64(len(*input))/float64(groupsize)))*(groupsize+1))
	runeCount := 0
	outCount := 0
	for i := 0; i < len(*input); i++ {
		output = append(output, (*input)[i])
		outCount++
		runeCount++
		if runeCount == groupsize {
			if i != len(*input)-1 {
				if columns > 0 && outCount >= columns-groupsize-1 {
					output = append(output, []rune(LineBreak)...)
					outCount = 0
				} else {
					output = append(output, rune(' '))
					outCount++
				}
			}
			runeCount = 0
		}
	}
	return &output, nil
}

// AllNeedlesInHaystack returns true is all needles can be found in the
// haystack. Final variadic is optional, first true will match case-insensitive
// instead of matching case. Intended to find Keepers of Keys where needles are
// Message.Recipients and haystack is Key.Keepers.
func AllNeedlesInHaystack(needles *[][]rune, haystack *[][]rune, caseInsensitive ...bool) bool {
	if needles == nil || haystack == nil {
		return false
	}
	if len(*needles) == 0 || len(*haystack) == 0 {
		return false
	}
loop:
	for i := range *needles {
		for x := range *haystack {
			if len(caseInsensitive) > 0 && caseInsensitive[0] {
				if EqualRunesFold(&(*haystack)[x], &(*needles)[i]) {
					continue loop
				}
			} else {
				if EqualRunes(&(*haystack)[x], &(*needles)[i]) {
					continue loop
				}
			}
		}
		return false
	}
	return true
}

func AnyNeedleInHaystack(needles *[][]rune, haystack *[][]rune) bool {
	if needles == nil || haystack == nil {
		return false
	}
	if len(*needles) == 0 || len(*haystack) == 0 { // do not need len(*needles), but be explicit
		return false
	}
	for i := range *needles {
		for x := range *haystack {
			if EqualRunes(&(*haystack)[x], &(*needles)[i]) {
				return true
			}
		}
	}
	return false
}

func AnyOfThem(haystack *[][]rune, needle *[]rune) bool {
	if haystack == nil || needle == nil {
		return false
	}
	if len(*needle) == 0 {
		return false
	}
	for i := range *haystack {
		if EqualRunes(&(*haystack)[i], needle) {
			return true
		}
	}
	return false
}

// Generic function to convert an array of rune slices (runes) into a string
// slice.
func RunesToStrings(runes *[][]rune) (stringSlice []string) {
	for i := range *runes {
		stringSlice = append(stringSlice, string((*runes)[i]))
	}
	return
}

// Wrapper to strings.Join for a pointer to slices of rune slices. Returns a
// string with 'separator' as delimiter between items.
func JoinRunesToString(runes *[][]rune, separator string) string {
	return strings.Join(RunesToStrings(runes), separator)
}

// Generic function to vet one or more keeper strings, comma/space-separated or
// not. Returns a slice of rune slices with the keepers for use in e.g
// Key.Keepers.
func VettedKeepers(keepers ...string) (vettedKeepers [][]rune) {
	f := func(c rune) bool {
		return c == ',' || c == ' '
	}
	for i := range keepers {
		subKeepers := strings.FieldsFunc(keepers[i], f)
		for a := range subKeepers {
			vettedKeeper := []rune(strings.ToUpper(strings.TrimSpace(subKeepers[a])))
			if len(vettedKeeper) > 0 {
				vettedKeepers = append(vettedKeepers, vettedKeeper)
			}
		}
	}
	return
}

// VettedRecipients is an alias for VettedKeepers.
func VettedRecipients(recipients ...string) [][]rune {
	return VettedKeepers(recipients...)
}

// VettedCallSigns is an alias for VettedKeepers.
func VettedCallSigns(callsigns ...string) [][]rune {
	return VettedKeepers(callsigns...)
}

// VettedKeys is an alias for VettedKeepers.
func VettedKeys(keys ...string) [][]rune {
	return VettedKeepers(keys...)
}

// Compare two rune slices. Returns true if they are equal, false if
// not.
func EqualRunes(a *[]rune, b *[]rune) bool {
	if a == nil && b == nil {
		return true
	}
	if a == nil || b == nil {
		return false
	}
	if len(*a) != len(*b) {
		return false
	}
	for x := range *a {
		if (*a)[x] != (*b)[x] {
			return false
		}
	}
	return true
}

// Same as EqualRunes, except EqualRunesFold is case-insensitive. Returns true
// if they are equal fold, false if not.
func EqualRunesFold(a *[]rune, b *[]rune) bool {
	if a == nil && b == nil {
		return true
	}
	if a == nil || b == nil {
		return false
	}
	if len(*a) != len(*b) {
		return false
	}
	for x := range *a {
		if unicode.ToUpper((*a)[x]) != unicode.ToUpper((*b)[x]) {
			return false
		}
	}
	return true
}

// ColumnSizes calculates max length of each []rune in a slice of []rune slices.
// If optional column headers are provided (as a string slice), their length
// will be taken into account as well. Left for legacy, replaced by
// predictColumnSizes().
func ColumnSizes(rs [][][]rune, headerFields ...string) (columnSizes []int) {
	for item := range rs {
		for col := range rs[item] {
			ilen := len(rs[item][col])
			if len(headerFields) >= col {
				hlen := len(headerFields[col])
				if hlen > ilen {
					ilen = hlen
				}
			}
			if len(columnSizes) <= col {
				columnSizes = append(columnSizes, ilen)
			} else {
				if columnSizes[col] < ilen {
					columnSizes[col] = ilen
				}
			}
		}
	}
	return
}

// Function internal to SummaryOfKeys(), faster than previous method (digest and
// ColumnSizes). Assumes the following header:
//
// []string{"ID", "KEEPERS", "CREATED", "EXPIRES", "USED", "COMPROMISED", "COMMENT"}
func predictColumnSizesOfKeys(keys []*Key) (columnSizes [7]int) {
	if len(keys) > 0 {
		if keys[0] == nil {
			return
		}
		// Just assume key length is the instance's group size of the first key in
		// the slice.
		columnSizes[0] = keys[0].instance.GroupSize
		// Keepers header is the initial length of the keepers column
		columnSizes[1] = len("KEEPERS")
		// Created and Expires are fixed length
		columnSizes[2] = len("012345ZJAN23")
		columnSizes[3] = len("012345ZJAN23")
		// Used and Compromised are normally the length of their headers
		columnSizes[4] = HighestInt(len(Words["No"]), len(Words["Yes"]), len("USED"))
		columnSizes[5] = HighestInt(len(Words["No"]), len(Words["Yes"]), len("COMPROMISED"))
		for i := range keys {
			if keys[i] == nil {
				continue
			}
			var keepersLength int
			if len(keys[i].Keepers) == 0 {
				keepersLength = len("Anonymous")
				if columnSizes[1] < keepersLength {
					columnSizes[1] = keepersLength
				}
			} else {
				for x := range keys[i].Keepers {
					keepersLength += len(keys[i].Keepers[x]) + 1
				}
				if keepersLength > 0 && columnSizes[1] < keepersLength {
					columnSizes[1] = keepersLength - 1
				}
			}
			clen := len(keys[i].Comment)
			if columnSizes[6] < clen {
				columnSizes[6] = clen
			}
		}
	}
	return
}

func padding(s []rune, fieldLength int) (spaces []rune) {
	padCount := fieldLength - len(s)
	for x := 0; x < padCount; x++ {
		spaces = append(spaces, rune(' '))
	}
	return
}

func withPadding(s []rune, fieldLength int) []rune {
	return append(s, padding(s, fieldLength)...)
}

// Maximum int in int slice. Alternative MaxInt function.
func HighestInt(number ...int) (highest int) {
	if len(number) == 0 {
		return 0
	}
	//highest = -int(^uint(0)>>1) - 1
	highest = math.MinInt
	for _, n := range number {
		if n > highest {
			highest = n
		}
	}
	return
}

// Minimum int in int slice. Alternative MinInt function.
func LowestInt(number ...int) (lowest int) {
	if len(number) == 0 {
		return 0
	}
	//lowest = int(^uint(0) >> 1)
	lowest = math.MaxInt
	for _, n := range number {
		if n < lowest {
			lowest = n
		}
	}
	return
}

// Returns a copy of a rune slice.
func RuneCopy(src *[]rune) []rune {
	if src == nil {
		return []rune{}
	}
	runeCopy := make([]rune, len(*src))
	copy(runeCopy, *src)
	return runeCopy
}

func RunePtr(s []rune) *[]rune {
	return &s
}

// Returns a copy of a byte slice.
func ByteCopy(src *[]byte) []byte {
	if src == nil {
		return []byte{}
	}
	byteCopy := make([]byte, len(*src))
	copy(byteCopy, *src)
	return byteCopy
}

func BytePtr(s []byte) *[]byte {
	return &s
}

func WithoutLineBreaks(text string) string {
	return regexp.MustCompile(`\r?\n`).ReplaceAllString(text, " ")
}
