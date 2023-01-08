package krypto431

import (
	_ "embed"
	"fmt"
	"os"

	"github.com/jung-kurt/gofpdf"
	"github.com/sa6mwa/blox"
	"github.com/sa6mwa/krypto431/diana"
)

//go:embed fonts/LiberationMono-Bold.ttf
var fontLiberationMonoBold []byte

//go:embed fonts/LICENSE
var fontLiberationMonoBoldLicense string

//go:embed LICENSE
var license string

var (
	KeyFooter string = `` +
		`CODING LEGEND                                              > Switch table (Z)` + LineBreak +
		`IDX A B C D E F G H I J K L M N O P Q R S T U V W X Y Z    ¤ Toggle binary mode (W)` + LineBreak +
		`CT1 A B C D E F G H I J K L M N O P   R S T U V W X Y >    ↕ Toggle case (X)` + LineBreak +
		`CT2 0 1 2 3 4 5 6 7 8 9 ? - Å Ä Ö . Q , Z : + / ¤ ↕ → >    → Change key (Y)` + LineBreak

	// Original legend, unable to get these unicodes working with gofpdf.
	// KeyFooter string = `` +
	// 	`CODING LEGEND                                              ⎘ Switch table (Z)` + LineBreak +
	// 	`IDX A B C D E F G H I J K L M N O P Q R S T U V W X Y Z    ⬔ Toggle binary mode (W)` + LineBreak +
	// 	`CT1 A B C D E F G H I J K L M N O P   R S T U V W X Y ⎘    ↕ Toggle case (X)` + LineBreak +
	// 	`CT2 0 1 2 3 4 5 6 7 8 9 ? - Å Ä Ö . Q , Z : + / ⬔ ↕ ⌥ ⎘    ⌥ Change key (Y)` + LineBreak
)

// Key_String returns a fully printable key with the DIANA reciprocal table and
// coding legend. Instructions are not included in the output.
func (k *Key) String() string {
	// Setup the key Blox canvas...
	fieldPadding := 3
	headerLines := 4
	footerLines := blox.LineCount(KeyFooter)
	rtLength, rtLines := blox.RowAndColumnCount(diana.ReciprocalTable)
	groups := ""
	rptr, _ := k.GroupsBlock()
	if rptr != nil {
		groups = string(*rptr)
	}
	groupsLength, groupsLines := blox.RowAndColumnCount(groups)
	groupsLineSpacing := 1
	if groupsLines*2-1 <= rtLines {
		groupsLineSpacing = 2
	}
	// Do not allow less than a certain minimum column size (length).
	cols := rtLength + fieldPadding + groupsLength
	if k.instance.Columns > cols {
		cols = k.instance.Columns
	}
	// Calculate rows...
	rows := headerLines + footerLines
	if rtLines > groupsLines*groupsLineSpacing {
		rows += rtLines
	} else {
		rows += groupsLines * groupsLineSpacing
	}

	keepers := "NIL"
	if len(k.Keepers) > 0 {
		keepers = k.JoinKeepers(",")
	}
	header := fmt.Sprintf("/ KEEPERS: %s / EXPIRES: %s / CREATED: %s / USED: [%s]",
		keepers, k.Expires, k.Created, k.UsedOrNotString("X", " "))

	// Just because you can...
	return blox.New().SetColumnsAndRows(cols, rows).Trim().
		DrawSeparator('_').PutTextRightAligned(header).Move(0, 1).
		PutLine(k.Id).MoveDown().DrawSeparator().MoveDown().PushPos().
		PutTextRightAligned(diana.ReciprocalTable).PopPos().
		SetLineSpacing(groupsLineSpacing).PutText(groups).SetLineSpacing(1).
		Move(0, rows-footerLines).PutText(KeyFooter).String()
}

func (m *Message) String() string {
	// Only the header is formatted using blox for messages...

	leftBox := 


	152000JDEC22         TO: SA6MWA,SA6MWA/P,SA6MWA
KEY: ABCDE    FROM (DE): QJ




	b := blox.New().SetColumnsAndRows()

}

func (k *Krypto431) KeysAsText(filter func(key *Key) bool) string {
	return ""
}

func (k *Krypto431) MessagesAsText(filter func(msg *Message) bool) string {
	return ""
}

func (k *Krypto431) KeysTextFile(filter func(key *Key) bool, filename string) error {
	return nil
}

func (k *Krypto431) MessagesTextFile(filter func(msg *Message) bool, filename string) error {
	return nil
}

func (k *Krypto431) KeysPDF(filter func(key *Key) bool, filename string) error {
	// A page will hold 110x87 characters
	var kp []*Key
	for i := range k.Keys {
		if filter(&k.Keys[i]) {
			kp = append(kp, &k.Keys[i])
		}
	}
	if len(kp) == 0 {
		fmt.Fprintf(os.Stderr, "There are no keys to print from %s.", k.GetPersistence())
		return nil
	}
	pdf := gofpdf.New("P", "mm", "A4", "")
	pdf.AddUTF8FontFromBytes("LiberationMono", "B", fontLiberationMonoBold)
	pdf.SetFont("LiberationMono", "B", 8)
	maxRows := 87
	rowCount := 0
	var page string
	for i := range kp {
		text := kp[i].String()
		textLines := blox.LineCount(text) + 5
		if textLines > maxRows {
			pdf.AddPage()
			pdf.MultiCell(0, 3, text, "", "", false)
			rowCount = 0
			continue
		}
		rowCount += textLines
		if rowCount > maxRows {
			pdf.AddPage()
			pdf.MultiCell(0, 3, page, "", "", false)
			rowCount = textLines
			page = ""
		}
		page = page + text + LineBreak + LineBreak + LineBreak + LineBreak + LineBreak
	}
	pdf.AddPage()
	pdf.MultiCell(0, 3, page, "", "", false)
	return pdf.OutputFileAndClose(filename)
}

func (k *Krypto431) MessagesPDF(filter func(key *Message) bool, filename string) error {
	// A page will hold 110x87 characters
	return nil
}
