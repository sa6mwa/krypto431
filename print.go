package krypto431

import (
	"fmt"

	"github.com/sa6mwa/blox"
	"github.com/sa6mwa/krypto431/diana"
)

var (
	KeyFooter string = `` +
		`CODING LEGEND                                              ⎘ Switch table (Z)` + LineBreak +
		`IDX A B C D E F G H I J K L M N O P Q R S T U V W X Y Z    ⬔ Toggle binary mode (W)` + LineBreak +
		`CT1 A B C D E F G H I J K L M N O P   R S T U V W X Y ⎘    ↕ Toggle case (X)` + LineBreak +
		`CT2 0 1 2 3 4 5 6 7 8 9 ? - Å Ä Ö . Q , Z : + / ⬔ ↕ ⌥ ⎘    ⌥ Change key (Y)` + LineBreak
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

	keepers := "<N/A>"
	if len(k.Keepers) > 0 {
		keepers = k.JoinKeepers(",")
	}
	header := fmt.Sprintf("/ KEEPERS: %s / EXPIRES: %s / CREATED: %s / USED: [%s]",
		keepers, k.Expires, k.Created, k.UsedOrNotString("Y", " "))

	// Just because you can...
	return blox.New().SetColumnsAndRows(cols, rows).Trim().
		DrawSeparator('_').PutTextRightAligned(header).Move(0, 1).
		PutLine(k.Id).MoveDown().DrawSeparator().MoveDown().PushPos().
		PutTextRightAligned(diana.ReciprocalTable).PopPos().
		SetLineSpacing(groupsLineSpacing).PutText(groups).SetLineSpacing(1).
		Move(0, rows-footerLines).PutText(KeyFooter).String()
}
