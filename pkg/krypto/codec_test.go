package krypto

import (
	"testing"
)

func Test_PlainText_Encode(t *testing.T) {
	testTable := []struct {
		text    []rune
		encoded []rune
	}{
		{[]rune("This is a test message."), []rune("TZVZZHISQISQAQTESTQMESSAGEZZP")},
		{[]rune("THIS IS A MESSAGE IN ALL CAPS, BUT IS IT TRUELY WORKING?"), []rune("THISQISQAQMESSAGEQINQALLQCAPSZZDZQBUTQISQITQTRUELYQWORKINGZZI")},
		{[]rune("QUEEN & ZERBA WENT TO Quebec FOR SOME AQUA OR Aqua"), []rune("ZQXUEENQZZNZQZSXERBAQWENTQTOQZQVZZUEBECQZVXFORQSOMEQAZQXUAQORQAZVQZZUA")},
	}

	for _, table := range testTable {
		p := &PlainText{
			Text: table.text,
		}
		err := p.Encode()
		if err != nil {
			t.Fatal(err)
		}
		if string(table.encoded) != string(p.EncodedText) {
			t.Errorf("Got \"%s\", but wanted \"%s\"", string(p.EncodedText), string(table.encoded))
		}
	}

}
