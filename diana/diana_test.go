package diana

import (
	"bytes"
	"testing"
)

func TestTrigraphRune(t *testing.T) {
	testTable := []struct {
		x, y, trigraph rune
	}{
		{'L', 'T', 'V'},
		{'U', 'Q', 'P'},
		{'W', 'I', 'V'},
		{'A', 'K', 'P'},
		{'J', 'M', 'E'},
		{'P', 'V', 'P'},
		{'X', 'K', 'S'},
		{'A', 'A', 'Z'},
		{'Z', 'Z', 'B'},
		{'Z', 'X', 'D'},
		{'K', 'Z', 'Q'},
	}
	for _, test := range testTable {
		scenarios := []struct {
			expected rune
			a        rune
			b        rune
		}{
			{test.trigraph, test.x, test.y},
			{test.trigraph, test.y, test.x},
			{test.x, test.y, test.trigraph},
			{test.y, test.x, test.trigraph},
			{test.y, test.trigraph, test.x},
			{test.x, test.trigraph, test.y},
		}
		t.Logf("X/Y/trigraph combos on: %c %c %c", test.x, test.y, test.trigraph)
		for _, scenario := range scenarios {
			var output rune
			err := TrigraphRune(&output, &scenario.a, &scenario.b)
			if err != nil {
				t.Fatal(err)
			}
			if output != scenario.expected {
				t.Errorf("Got trigraph %c, expected %c (%c, %c, %c)", output, scenario.expected, scenario.expected, scenario.a, scenario.b)
			}
		}
	}
}

func TestTrigraphByte(t *testing.T) {
	testTable := []struct {
		x, y, trigraph byte
	}{
		{'L', 'T', 'V'},
		{'U', 'Q', 'P'},
		{'W', 'I', 'V'},
		{'A', 'K', 'P'},
		{'J', 'M', 'E'},
		{'P', 'V', 'P'},
		{'X', 'K', 'S'},
		{'A', 'A', 'Z'},
		{'Z', 'Z', 'B'},
		{'Z', 'X', 'D'},
		{'K', 'Z', 'Q'},
	}
	for _, test := range testTable {
		scenarios := []struct {
			expected byte
			a        byte
			b        byte
		}{
			{test.trigraph, test.x, test.y},
			{test.trigraph, test.y, test.x},
			{test.x, test.y, test.trigraph},
			{test.y, test.x, test.trigraph},
			{test.y, test.trigraph, test.x},
			{test.x, test.trigraph, test.y},
		}
		t.Logf("X/Y/trigraph combos on: %c %c %c", test.x, test.y, test.trigraph)
		for _, scenario := range scenarios {
			var output byte
			err := TrigraphByte(&output, &scenario.a, &scenario.b)
			if err != nil {
				t.Fatal(err)
			}
			if output != scenario.expected {
				t.Errorf("Got trigraph %c, expected %c (%c, %c, %c)", output, scenario.expected, scenario.expected, scenario.a, scenario.b)
			}
		}
	}
}

func TestZeroKeyRune(t *testing.T) {
	input := []rune("HELLOWORLD")
	zerokey := []rune("LRDDXHXRDT")

	for i, c := range input {
		var output rune
		err := ZeroKeyRune(&output, &c)
		if err != nil {
			t.Fatal(err)
		}
		if output != zerokey[i] {
			t.Errorf("Got %c, expected %c", output, zerokey[i])
		}
	}
	for i, c := range zerokey {
		var output rune
		t.Logf("Zerokey trigraph %c %c %c", input[i], c, input[i])
		err := TrigraphRune(&output, &c, &input[i])
		if err != nil {
			t.Fatal(err)
		}
		if output != input[i] {
			t.Errorf("Got %c, expected %c", output, input[i])
		}
	}
}

func TestZeroKeyByte(t *testing.T) {
	input := []byte("HELLOWORLD")
	zerokey := []byte("LRDDXHXRDT")

	for i, c := range input {
		var output byte
		err := ZeroKeyByte(&output, &c)
		if err != nil {
			t.Fatal(err)
		}
		if output != zerokey[i] {
			t.Errorf("Got %c, expected %c", output, zerokey[i])
		}
	}
	for i, c := range zerokey {
		var output byte
		t.Logf("Zerokey trigraph %c %c %c", input[i], c, input[i])
		err := TrigraphByte(&output, &c, &input[i])
		if err != nil {
			t.Fatal(err)
		}
		if output != input[i] {
			t.Errorf("Got %c, expected %c", output, input[i])
		}
	}
}

func TestTrigraphRuneBadInput(t *testing.T) {
	var bogus rune
	scenarios := []struct {
		a, b, c *rune
	}{
		{&bogus, nil, nil},
		{nil, &bogus, &bogus},
		{&bogus, &bogus, nil},
	}
	for _, s := range scenarios {
		err := TrigraphRune(s.a, s.b, s.c)
		if err == nil {
			t.Error("Expected nil input to fail")
		}
	}
}

func TestTrigraphByteBadInput(t *testing.T) {
	var bogus byte
	scenarios := []struct {
		a, b, c *byte
	}{
		{&bogus, nil, nil},
		{nil, &bogus, &bogus},
		{&bogus, &bogus, nil},
	}
	for _, s := range scenarios {
		err := TrigraphByte(s.a, s.b, s.c)
		if err == nil {
			t.Error("Expected nil input to fail")
		}
	}
}

func TestTrigraphRuneInvalidCharacters(t *testing.T) {
	scenarios := []struct {
		a, b rune
	}{
		{'a', 'z'},
		{'&', '%'},
		{'Z', 'z'},
		{'a', 'B'},
		{'A', 'a'},
	}
	for _, test := range scenarios {
		var output rune
		err := TrigraphRune(&output, &test.a, &test.b)
		if err == nil {
			t.Error("Expected non A to Z character input to fail")
		}
	}
}

func TestTrigraphByteInvalidCharacters(t *testing.T) {
	scenarios := []struct {
		a, b byte
	}{
		{'a', 'z'},
		{'&', '%'},
		{'Z', 'z'},
		{'a', 'B'},
		{'A', 'a'},
	}
	for _, test := range scenarios {
		var output byte
		err := TrigraphByte(&output, &test.a, &test.b)
		if err == nil {
			t.Error("Expected non A to Z character input to fail")
		}
	}
}

func TestAppendTrigraphByteByKey(t *testing.T) {
	scenarios := []struct {
		expected []byte
		text     []byte
		key      []byte
	}{
		{[]byte("HELLOWORLD"), []byte("HELLOWORLD"), []byte("LRDDXHXRDT")},
	}

	for _, test := range scenarios {
		keyIndex := int(0)
		output := make([]byte, 0, 20)
		for i := range test.text {
			err := AppendTrigraphByteByKey(&output, &test.text[i], &test.key, &keyIndex)
			if err != nil {
				t.Fatal(err)
			}
		}
		if bytes.Compare(output, test.expected) != 0 {
			t.Errorf("Not the same: %c and %c", output, test.expected)
		}
	}
}

func TestAppendTrigraphByteByKeyBadInput(t *testing.T) {
	var (
		key         []byte = []byte("LRDDXHXRDT")
		idx         int    = int(0)
		negativeIdx int    = int(-1)
		tooLargeIdx int    = int(1)
		output      []byte
		char        byte = byte('A')
		badChar     byte = byte('a')
	)

	scenarios := []struct {
		writeTo   *[]byte
		character *byte
		key       *[]byte
		keyIndex  *int
	}{
		{nil, nil, nil, nil},
		{nil, &char, &key, &idx},
		{&output, &char, nil, &idx},
		{&output, &char, &key, nil},
		{&output, nil, &key, &idx},
		{&output, &char, &key, &negativeIdx},
		{&output, &char, &key, &tooLargeIdx},
		{&output, &badChar, &key, &idx},
	}

	for _, test := range scenarios {
		err := AppendTrigraphByteByKey(test.writeTo, test.character, test.key, test.keyIndex)
		if err == nil {
			t.Error("Expected AppendTrigraphByteByKey too fail!")
		}
	}
}
