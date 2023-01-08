package keydir

// Re-implementation of https://rosettacode.org/wiki/Natural_sorting#Go

import (
	"regexp"
	"strconv"
	"strings"
)

var dx = regexp.MustCompile(`\d+|\D+`)

// natStr associates a string with a preprocessed form
type natStr struct {
	s string // original
	t []tok  // preprocessed "sub-fields"
}

// rule is to use s unless it is empty, then use n
type tok struct {
	s string
	n int
}

func newNatStr(s string) (t natStr) {
	t.s = s
	s = strings.ToLower(strings.Join(strings.Fields(s), " "))
	x := dx.FindAllString(s, -1)
	t.t = make([]tok, len(x))
	for i, s := range x {
		if n, err := strconv.Atoi(s); err == nil {
			t.t[i].n = n
		} else {
			t.t[i].s = s
		}
	}
	return t
}

func (a tok) cmp(b tok) int {
	switch {
	case a.s == "":
		switch {
		case b.s > "" || a.n < b.n:
			return -1
		case a.n > b.n:
			return 1
		}
	case b.s == "" || a.s > b.s:
		return 1
	case a.s < b.s:
		return -1
	}
	return 0
}

func natLess(a, b natStr) bool {
	ti := a.t
	for k, t := range b.t {
		if k == len(ti) {
			return true
		}
		switch ti[k].cmp(t) {
		case -1:
			return true
		case 1:
			return false
		}
	}
	return false
}
