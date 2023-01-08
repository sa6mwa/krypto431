package krypto431

import (
	_ "embed"
	"errors"
	"fmt"
	"os"
	"strings"
	"unicode/utf8"

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

// Message_String returns a formatted output intended to print. By default the
// width is 80 to fit consoles, but can be changed with the optional width
// variadic (first item in slice is used for column width).
func (m *Message) String(width ...int) string {
	w := 80
	// Messages seemed less complicated to format, but...
	templateDtgAndKey := `` +
		`                  ` + LineBreak +
		`ID:               ` + LineBreak
	templateToFrom := `` +
		`       TO: ` + LineBreak +
		`FROM (DE): ` + LineBreak
	var keyid string
	if len(m.KeyId) > 0 {
		keyid = string(m.KeyId)
	} else {
		keyid = string(NilRunes)
	}
	var recipientsString string
	if len(m.Recipients) > 0 {
		recipientsString = m.JoinRecipients(",")
	} else {
		recipientsString = string(NilRunes)
	}
	tDtgKeyLen := blox.MaximumLineLength(templateDtgAndKey)
	tToFromLen := blox.MaximumLineLength(templateToFrom)
	minWidth := tDtgKeyLen + tToFromLen + HighestInt(utf8.RuneCountInString(recipientsString), len(keyid))
	if len(width) > 0 {
		if width[0] < minWidth {
			w = minWidth
		} else {
			w = width[0]
		}
	}
	b := blox.New().SetColumnsAndRows(w, 3).Trim()
	b.DrawSeparator('_').PushPos().PushPos().PutText(templateDtgAndKey).PopPos().
		MoveX(tDtgKeyLen).PutText(templateToFrom).PopPos().
		PutText(m.DTG.String()).MoveX(4).PutText(m.IdString()).
		MoveUp().MoveX(tDtgKeyLen + tToFromLen).
		PutText(recipientsString).
		PutText(string(m.From))

	output := b.String()

	wrappedPlainText := blox.WrapString(blox.WithoutLineBreaks(string(m.PlainText)), uint(w))
	g, _ := m.Groups()
	if g == nil {
		tmp := make([]rune, 0)
		g = &tmp
	}
	if utf8.RuneCountInString(wrappedPlainText) > 0 {
		output += "=TEXT=" + LineBreak + wrappedPlainText + LineBreak
	}

	var groupsPrependedWithKey string
	if len(*g) > 0 {
		groupsPrependedWithKey = string(m.KeyId) + " " + string(*g)
	}
	wrappedCipherText := blox.WrapString(groupsPrependedWithKey, uint(w))
	if utf8.RuneCountInString(wrappedCipherText) > 0 {
		output += "=CIPHER=" + LineBreak + wrappedCipherText + LineBreak
		groupCount := len(strings.Fields(wrappedCipherText))
		traffic := blox.WrapString(strings.TrimSpace(fmt.Sprintf("%s DE %s %s %d = %s = K", m.JoinRecipients(" "), string(m.From), m.DTG.String(), groupCount, groupsPrependedWithKey)), uint(w))
		output += "=TRAFFIC=EXAMPLE=" + LineBreak + traffic + LineBreak
	}

	return output
}

// KeysAsText returns a formatted multi-line string with all keys according to
// filter function. For example, to return all keys not marked `used` as one big
// printable string...
//
//	s := krypto431.KeysAsText(func(k *krypto431.Key) bool { return !k.Used })
func (k *Krypto431) KeysAsText(filter func(key *Key) bool) string {
	var kp []*Key
	for i := range k.Keys {
		if filter(&k.Keys[i]) {
			kp = append(kp, &k.Keys[i])
		}
	}
	if len(kp) == 0 {
		fmt.Fprintf(os.Stderr, "There are no keys to format from %s."+LineBreak, k.GetPersistence())
		return ""
	}
	var output string
	for i := range kp {
		output += kp[i].String() + LineBreak
	}
	return output
}

// MessagesAsText returns a formatted multi-line string with all messages according to filter function.
// For example, to return all messages as one big printable string...
//
//	s := krypto431.MessagesAsText(func(k *krypto431.Message) bool { return true })
func (k *Krypto431) MessagesAsText(filter func(msg *Message) bool) string {
	var mp []*Message
	for i := range k.Messages {
		if filter(&k.Messages[i]) {
			mp = append(mp, &k.Messages[i])
		}
	}
	if len(mp) == 0 {
		fmt.Fprintf(os.Stderr, "There are no messages to format from %s."+LineBreak, k.GetPersistence())
		return ""
	}
	var output string
	for i := range mp {
		output += mp[i].String() + LineBreak
	}
	return output
}

func (k *Krypto431) KeysTextFile(filter func(key *Key) bool, filename string) error {
	bigStringOfKeys := k.KeysAsText(filter)
	if bigStringOfKeys == "" {
		return errors.New("no keys to write to file (empty set)")
	}
	f, err := os.OpenFile(filename, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.WriteString(bigStringOfKeys)
	if err != nil {
		return err
	}
	return nil
}

func (k *Krypto431) MessagesTextFile(filter func(msg *Message) bool, filename string) error {
	bigStringOfMessages := k.MessagesAsText(filter)
	if bigStringOfMessages == "" {
		return errors.New("no messages to write to file (empty set)")
	}
	f, err := os.OpenFile(filename, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.WriteString(bigStringOfMessages)
	if err != nil {
		return err
	}
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
		fmt.Fprintf(os.Stderr, "There are no keys to print from %s."+LineBreak, k.GetPersistence())
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
	// TODO: this will probably produce an empty page if only one key fits the
	// page...
	pdf.AddPage()
	pdf.MultiCell(0, 3, page, "", "", false)
	return pdf.OutputFileAndClose(filename)
}

func (k *Krypto431) MessagesPDF(filter func(msg *Message) bool, filename string) error {
	var mp []*Message
	for i := range k.Messages {
		if filter(&k.Messages[i]) {
			mp = append(mp, &k.Messages[i])
		}
	}
	if len(mp) == 0 {
		fmt.Fprintf(os.Stderr, "There are no messages to print from %s."+LineBreak, k.GetPersistence())
		return nil
	}
	pdf := gofpdf.New("P", "mm", "A4", "")
	pdf.AddUTF8FontFromBytes("LiberationMono", "B", fontLiberationMonoBold)
	// A page will hold 97x65
	pdf.SetFont("LiberationMono", "B", 9)
	maxRows := 65
	rowCount := 0
	var page string
	for i := range mp {
		text := mp[i].String(95)
		textLines := blox.LineCount(text) + 2
		if textLines > maxRows {
			pdf.AddPage()
			pdf.MultiCell(0, 4, text, "", "", false)
			rowCount = 0
			continue
		}
		rowCount += textLines
		if rowCount > maxRows {
			pdf.AddPage()
			pdf.MultiCell(0, 4, page, "", "", false)
			rowCount = textLines
			page = ""
		}
		page = page + text + LineBreak + LineBreak
	}
	// TODO: this will probably produce an (extra) empty page if message is longer
	// than maxRows...
	pdf.AddPage()
	pdf.MultiCell(0, 4, page, "", "", false)
	return pdf.OutputFileAndClose(filename)
}
