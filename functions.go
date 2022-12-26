package krypto431

import (
	"errors"
	"math"
	"strings"
	"unicode"
)

// Functions not assigned to methods of more general use likely end up here.

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
// haystack. Intended to find Keepers of Keys where needles are
// Message.Recipients and haystack is Key.Keepers.
func AllNeedlesInHaystack(needles *[][]rune, haystack *[][]rune) bool {
	if needles == nil || haystack == nil {
		return false
	}
	if len(*needles) == 0 || len(*haystack) == 0 {
		return false
	}
loop:
	for i := range *needles {
		for x := range *haystack {
			if EqualRunes(&(*haystack)[x], &(*needles)[i]) {
				continue loop
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
	if len(*needles) == 0 || len(*haystack) == 0 {
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

// Function to compare two rune slices. Returns true if they are equal, false if
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
// Intended to be used to format multiple responses from Key.Digest() and
// Message.Digest() for printing.
func ColumnSizes(headerFields []string, rs [][][]rune) (columnSizes []int) {
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

// Returns a copy of a rune slice.
func RuneCopy(src *[]rune) []rune {
	if src == nil {
		return []rune{}
	}
	runeCopy := make([]rune, len(*src))
	copy(runeCopy, *src)
	return runeCopy
}
