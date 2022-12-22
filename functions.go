package krypto431

import (
	"strings"
)

// Functions not assigned to methods of more general use likely end up here.

// AllNeedlesInHaystack returns true is all needles can be found in the
// haystack, but if one slice in the haystack is a star (*) it will always
// return true. Intended to find Keepers of Keys where needles are
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
			if string((*haystack)[x]) == `*` {
				return true
			}
			if string((*haystack)[x]) == string((*needles)[i]) {
				continue loop
			}
		}
		return false
	}
	return true
}

// Generic function to convert an array of rune slices (runes) into a string
// slice.
func RunesToStrings(runes *[][]rune) (stringSlice []string) {
	for i := range *runes {
		stringSlice = append(stringSlice, string((*runes)[i]))
	}
	return
}

// Generic function to vet one or more keeper strings, comma-separated or not.
func VettedKeepers(keepers ...string) (vettedKeepers [][]rune) {
	for i := range keepers {
		subKeepers := strings.Split(keepers[i], ",")
		for a := range subKeepers {
			vettedKeeper := []rune(strings.ToUpper(strings.TrimSpace(subKeepers[a])))
			if len(vettedKeeper) > 0 {
				vettedKeepers = append(vettedKeepers, vettedKeeper)
			}
		}
	}
	return
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
