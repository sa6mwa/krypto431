package blox

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"strings"
	"unicode"
	"unicode/utf8"
)

var (
	InitialCanvasCapacity      int  = 80 * 24
	InitialCanvasColumns       int  = 0
	InitialCanvasRows          int  = 0
	InitialCursorPositionX     int  = 0
	InitialCursorPositionY     int  = 0
	InitialLineSpacing         int  = 1
	InitialTrimRightSpaces     bool = true
	InitialTrimFinalEmptyLines bool = false
)

type Blox struct {
	Columns             int // X
	Rows                int // Y
	Cursor              CursorPosition
	CursorStack         []CursorPosition
	LineSpacing         int
	TrimRightSpaces     bool
	TrimFinalEmptyLines bool
	Canvas              []rune
}

type CursorPosition struct {
	X         int // Column
	Y         int // Row
	OffCanvas bool
}

func New() *Blox {
	b := Blox{
		Columns:             InitialCanvasColumns,
		Rows:                InitialCanvasRows,
		LineSpacing:         InitialLineSpacing,
		TrimRightSpaces:     InitialTrimRightSpaces,
		TrimFinalEmptyLines: InitialTrimFinalEmptyLines,
		Canvas:              make([]rune, 0, InitialCanvasCapacity),
	}
	b.ResizeCanvas().Move(InitialCursorPositionX, InitialCursorPositionY)
	return &b
}

func (b *Blox) Wipe() *Blox {
	for i := 0; i < len(b.Canvas); i++ {
		b.Canvas[i] = 0
	}
	b.Canvas = b.Canvas[:0]
	return b
}

func (b *Blox) ResizeCanvas() *Blox {
	have := len(b.Canvas)
	need := b.Columns * b.Rows
	if need > cap(b.Canvas) {
		tmp := make([]rune, need)
		copy(tmp, b.Canvas)
		b.Wipe()
		b.Canvas = tmp
	} else {
		b.Canvas = b.Canvas[:need]
	}
	if need > have {
		for i := 0; i < need-have; i++ {
			b.Canvas[have+i] = ' '
		}
	}
	return b.Move(b.Cursor.X, b.Cursor.Y)
}

func (b *Blox) SetColumns(columns int) *Blox {
	b.Columns = columns
	b.ResizeCanvas()
	return b
}

func (b *Blox) SetRows(rows int) *Blox {
	b.Rows = rows
	b.ResizeCanvas()
	return b
}

func (b *Blox) SetColumnsAndRows(columns int, rows int) *Blox {
	b.Columns = columns
	b.Rows = rows
	b.ResizeCanvas()
	return b
}

func (b *Blox) SetLineSpacing(n int) *Blox {
	b.LineSpacing = n
	return b
}

func (b *Blox) SetTrimRightSpaces(trim bool) *Blox {
	b.TrimRightSpaces = trim
	return b
}

func (b *Blox) SetTrimFinalEmptyLines(trim bool) *Blox {
	b.TrimFinalEmptyLines = trim
	return b
}

// SetTrim allow you to enable/disable trimming of trailing spaces and empty
// lines with the same function.
func (b *Blox) SetTrim(trim bool) *Blox {
	b.TrimRightSpaces = trim
	b.TrimFinalEmptyLines = trim
	return b
}

// Trim sets trimming of trailing spaces and trailing empty lines for String,
// Lines, Runes, PrintCanvas and similar output functions.
func (b *Blox) Trim() *Blox {
	return b.SetTrim(true)
}

// Move to a column/row position on the canvas where x is column and y is
// row, upp left hand corner is 0,0.
func (b *Blox) Move(x int, y int) *Blox {
	if x >= b.Columns {
		b.Cursor.OffCanvas = true
		if b.Columns > 0 {
			b.Cursor.X = b.Columns - 1
		} else {
			b.Cursor.X = 0
		}
	} else {
		b.Cursor.OffCanvas = false
		b.Cursor.X = x
	}
	if y >= b.Rows {
		b.Cursor.OffCanvas = true
		if b.Rows > 0 {
			b.Cursor.Y = b.Rows - 1
		} else {
			b.Cursor.Y = 0
		}
	} else {
		b.Cursor.Y = y
	}
	return b
}

func (b *Blox) MoveX(x int) *Blox {
	return b.Move(x, b.Cursor.Y)
}

func (b *Blox) MoveY(y int) *Blox {
	return b.Move(b.Cursor.X, y)
}

func (b *Blox) MoveRight(n ...int) *Blox {
	step := 1
	if len(n) > 0 && n[0] > step {
		step = n[0]
	}
	return b.Move(b.Cursor.X+step, b.Cursor.Y)
}

func (b *Blox) MoveLeft(n ...int) *Blox {
	step := 1
	if len(n) > 0 && n[0] > step {
		step = n[0]
	}
	if b.Cursor.X >= step {
		if b.Cursor.OffCanvas {
			return b.Move(b.Cursor.X-step+1, b.Cursor.Y)
		}
		return b.Move(b.Cursor.X-step, b.Cursor.Y)
	}
	return b.Move(0, b.Cursor.Y)
}

func (b *Blox) MoveDown(n ...int) *Blox {
	step := 1
	if len(n) > 0 && n[0] > step {
		step = n[0]
	}
	return b.Move(b.Cursor.X, b.Cursor.Y+step)
}

func (b *Blox) MoveUp(n ...int) *Blox {
	step := 1
	if len(n) > 0 && n[0] > step {
		step = n[0]
	}
	if b.Cursor.Y >= step {
		return b.Move(b.Cursor.X, b.Cursor.Y-step)
	}
	return b.Move(b.Cursor.X, 0)
}

func (b *Blox) PutLine(runes []rune) *Blox {
	for _, r := range runes {
		b.PutChar(r)
	}
	return b
}

func (b *Blox) PutChar(r rune) *Blox {
	if b.Cursor.X < b.Columns {
		switch {
		case r == '\n', r == '\r':
			return b
		}
		if !b.Cursor.OffCanvas {
			b.Canvas[b.CurrentIndex()] = r
		}
		b.MoveRight()
	}
	return b
}

func (b *Blox) PutLines(lines ...string) *Blox {
	if b.Rows == 0 || b.Columns == 0 {
		return b
	}
	originX := b.Cursor.X
	for _, line := range lines {
		b.PutLine([]rune(line))
		b.Move(originX, b.Cursor.Y+b.LineSpacing)
	}
	return b
}

func (b *Blox) PutText(text string) *Blox {
	if b.Rows == 0 || b.Columns == 0 {
		return b
	}
	originX := b.Cursor.X
	s := bufio.NewScanner(strings.NewReader(text))
	for s.Scan() {
		b.PutLine([]rune(s.Text())).Move(originX, b.Cursor.Y+b.LineSpacing)
	}
	return b
}

func (b *Blox) PutTextRightAligned(text string) *Blox {
	if b.Rows == 0 || b.Columns == 0 {
		return b
	}
	l := MaximumLineLength(text)
	alignedX := 0
	cropBeginningBy := 0
	if l > b.Columns {
		cropBeginningBy = l - b.Columns
	} else {
		alignedX = b.Columns - l
	}
	b.MoveX(alignedX)
	s := bufio.NewScanner(strings.NewReader(text))
	for s.Scan() {
		line := []rune(s.Text())
		if cropBeginningBy > 0 {
			if len(line) > cropBeginningBy {
				line = line[cropBeginningBy:]
			} else {
				line = line[0:0]
			}
		}
		b.PutLine(line).Move(alignedX, b.Cursor.Y+b.LineSpacing)
	}
	return b
}

func (b *Blox) FprintCanvas(o *os.File) *Blox {
	_, err := o.Write([]byte(b.String()))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v", err)
	}
	return b
}

func (b *Blox) PrintCanvas() *Blox {
	return b.FprintCanvas(os.Stdout)
}

// Lines is the main function for producing printable output. Returns each row
// as a slice of rune slices. Each line is with or without trailing space
// depending on if TrimRightSpaces is true or false (SetTrimRightSpaces).
func (b *Blox) Lines() [][]rune {
	lines := make([][]rune, 0, b.Rows)
	for r := 0; r < b.Rows; r++ {
		line := make([]rune, 0, b.Columns)
		for c := 0; c < b.Columns; c++ {
			i := b.Index(c, r)
			line = append(line, b.Canvas[i])
		}
		if b.TrimRightSpaces {
			for i := len(line); i > 0; i-- {
				if unicode.IsSpace(line[i-1]) {
					line = line[:i-1]
				} else {
					break
				}
			}
		}
		lines = append(lines, line)
	}
	if b.TrimFinalEmptyLines {
		for i := len(lines); i > 0; i-- {
			empty := len(lines[i-1]) == 0
			if !empty {
				for x := 0; x < len(lines[i-1]); x++ {
					if unicode.IsSpace(lines[i-1][x]) {
						empty = true
					} else {
						empty = false
						break
					}
				}
			}
			if empty {
				lines = lines[:i-1]
			} else {
				break
			}
		}
	}
	return lines
}

// Returns each row in the canvas as a string slice.
func (b *Blox) Strings() (lines []string) {
	for _, line := range b.Lines() {
		lines = append(lines, string(line))
	}
	return
}

// Joins all rows with the new-line separator and returns a rune slice.
func (b *Blox) Runes() []rune {
	lines := b.Lines()
	s := make([]rune, 0, (b.Columns*b.Rows)+(utf8.RuneCountInString(LineBreak)*b.Rows))
	for i := range lines {
		s = append(s, lines[i]...)
		s = append(s, []rune(LineBreak)...)
	}
	return s
}

func (b *Blox) String() string {
	return string(b.Runes())
}

// Join returns a string where each line is joined by sep, but does not end in
// sep like the String function (similar to strings.Join).
func (b *Blox) Join(sep string) string {
	lines := b.Lines()
	switch len(lines) {
	case 0:
		return ""
	case 1:
		return string(lines[0])
	}
	s := make([]rune, 0, (b.Columns*b.Rows)+(utf8.RuneCountInString(sep)*b.Rows))
	s = append(s, lines[0]...)
	for _, line := range lines[1:] {
		s = append(s, []rune(LineBreak)...)
		s = append(s, line...)
	}
	return string(s)
}

// Return current index to write/read to/from on canvas based on current cursor
// row/column position.
func (b *Blox) CurrentIndex() int {
	if b.Cursor.X*b.Cursor.Y >= len(b.Canvas) {
		if len(b.Canvas) > 0 {
			return len(b.Canvas) - 1
		} else {
			return 0
		}
	}
	return b.Cursor.Y*b.Columns + b.Cursor.X
}

// Return index to write/read to/from on canvas by row/col representation (x is
// column, y is row).
func (b *Blox) Index(x int, y int) int {
	if x*y >= len(b.Canvas) {
		if len(b.Canvas) > 0 {
			return len(b.Canvas) - 1
		} else {
			return 0
		}
	}
	return y*b.Columns + x

}

// DrawSeparator draws a horizontal line with hyphens (-) at the current
// row. You can change the default rune with the optional char.
func (b *Blox) DrawSeparator(char ...rune) *Blox {
	return b.DrawHorizontalLine(0, b.Columns, char...).MoveX(0).MoveDown()
}

// DrawSplit draws a vertical line with pipes (|) at the current column from the
// top row to the bottom row of the canvas. You can change the default rune with
// the optional char.
func (b *Blox) DrawSplit(char ...rune) *Blox {
	return b.DrawVerticalLine(0, b.Rows, char...)
}

// DrawHorizontalLine draws hyphens (-) horizontally between two X positions at
// the current row (Y). You can change the default rune with the optional char.
func (b *Blox) DrawHorizontalLine(fromX int, toX int, char ...rune) *Blox {
	if fromX > toX {
		return b
	}
	c := rune('-')
	if len(char) > 0 {
		c = char[0]
	}
	reps := toX - fromX
	b.Move(fromX, b.Cursor.Y)
	for i := 0; i <= reps; i++ {
		b.PutChar(c)
	}
	return b
}

// DrawVerticalLine draws pipes (|) vertically between two Y positions at the
// current column (X). You can change the default rune with the optional char.
func (b *Blox) DrawVerticalLine(fromY int, toY int, char ...rune) *Blox {
	if fromY > toY {
		return b
	}
	c := rune('|')
	if len(char) > 0 {
		c = char[0]
	}
	reps := toY - fromY
	b.Move(b.Cursor.X, fromY)
	for i := 0; i <= reps; i++ {
		b.PutChar(c).MoveLeft().MoveDown()
	}
	return b
}

// Save (push) current cursor position to the cursor stack.
func (b *Blox) PushPos() *Blox {
	c := CursorPosition{
		X:         b.Cursor.X,
		Y:         b.Cursor.Y,
		OffCanvas: b.Cursor.OffCanvas,
	}
	b.CursorStack = append(b.CursorStack, c)
	return b
}

// Restore (pop) last saved (pushed) cursor position from the cursor stack.
func (b *Blox) PopPos() *Blox {
	if len(b.CursorStack) > 0 {
		poppedCursor := b.CursorStack[len(b.CursorStack)-1]
		b.Move(poppedCursor.X, poppedCursor.Y)
		b.CursorStack = b.CursorStack[:len(b.CursorStack)-1]
	}
	return b
}

// RowAndColumnCount can be used to initialize a new canvas to fit
// Move(0,0).PutText(text) with lines of text for example. Returns x, y
// (column, row) where x represents the longest line count.
func RowAndColumnCount(text string) (int, int) {
	columnCount := 0
	lineCount := 0
	s := bufio.NewScanner(strings.NewReader(text))
	for s.Scan() {
		c := utf8.RuneCountInString(s.Text())
		if c > columnCount {
			columnCount = c
		}
		lineCount++
	}
	return columnCount, lineCount
}

// LineCount returns the number of lines (rows) in text (can be used to setup
// canvas Rows to fit text).
func LineCount(text string) int {
	lineCount := 0
	s := bufio.NewScanner(strings.NewReader(text))
	for s.Scan() {
		lineCount++
	}
	return lineCount
}

// MaximumLineLength returns number of runes in the longest line (can be used to
// setup canvas Columns to fit text).
func MaximumLineLength(text string) int {
	lineLength := 0
	s := bufio.NewScanner(strings.NewReader(text))
	for s.Scan() {
		c := utf8.RuneCountInString(s.Text())
		if c > lineLength {
			lineLength = c
		}
	}
	return lineLength
}

// CutLinesShort cuts several lines to maxLen and return the new text. Will trim
// trailing space if trimTrailingSpace is true.
func CutLinesShort(text string, maxLen int, trimTrailingSpace bool) string {
	newText := make([]rune, 0, utf8.RuneCountInString(text))
	s := bufio.NewScanner(strings.NewReader(text))
	for s.Scan() {
		line := s.Text()
		if trimTrailingSpace {
			line = strings.TrimRightFunc(CutLineShort(line, maxLen, false), unicode.IsSpace)
		} else {
			line = CutLineShort(line, maxLen, false)
		}
		newText = append(newText, []rune(line)...)
		newText = append(newText, []rune(LineBreak)...)
	}
	return string(newText)
}

// CutLineShort cuts line after maxLen adding dots if addThreeDots is true.
// Returns a shortened or the original string.
func CutLineShort(line string, maxLen int, addThreeDots bool) string {
	threeDots := '…'
	if utf8.RuneCountInString(line) > maxLen {
		l := []rune(line)
		c := len(l)
		if c == 0 || c < maxLen {
			return line
		}
		l = l[:maxLen]
		if addThreeDots {
			if len(l) > 0 {
				l[len(l)-1] = threeDots
			}
		}
		return string(l)
	}
	return line
}

// WithoutLineBreaks removes all line-feeds (well, not all) from s and returns a
// new string. See ReplaceLineBreaks instead.
func WithoutLineBreaks(s string) string {
	r := strings.NewReplacer("\r", "", "\n", "")
	return r.Replace(s)
}

// ReplaceLineBreaks replaces various breaks from s with replacement and returns
// a new string.
func ReplaceLineBreaks(s string, replacement string) string {
	r := strings.NewReplacer(
		"\r\n", replacement,
		"\r", replacement,
		"\n", replacement,
		"\v", replacement,
		"\f", replacement,
		"\u0085", replacement,
		"\u2028", replacement,
		"\u2029", replacement,
	)
	return r.Replace(s)
}

// WrapString is (C) 2014 Mitchell Hashimoto https://github.com/mitchellh
// Imported from https://github.com/mitchellh/go-wordwrap
//
// WrapString wraps the given string within lim width in characters.
//
// Wrapping is currently naive and only happens at white-space. A future
// version of the library will implement smarter wrapping. This means that
// pathological cases can dramatically reach past the limit, such as a very
// long word.
func WrapString(s string, lim uint) string {
	const nbsp = 0xA0
	// Initialize a buffer with a slightly larger size to account for breaks
	init := make([]byte, 0, len(s))
	buf := bytes.NewBuffer(init)

	var current uint
	var wordBuf, spaceBuf bytes.Buffer
	var wordBufLen, spaceBufLen uint

	for _, char := range s {
		if char == '\n' {
			if wordBuf.Len() == 0 {
				if current+spaceBufLen > lim {
					current = 0
				} else {
					current += spaceBufLen
					spaceBuf.WriteTo(buf)
				}
				spaceBuf.Reset()
				spaceBufLen = 0
			} else {
				current += spaceBufLen + wordBufLen
				spaceBuf.WriteTo(buf)
				spaceBuf.Reset()
				spaceBufLen = 0
				wordBuf.WriteTo(buf)
				wordBuf.Reset()
				wordBufLen = 0
			}
			buf.WriteRune(char)
			current = 0
		} else if unicode.IsSpace(char) && char != nbsp {
			if spaceBuf.Len() == 0 || wordBuf.Len() > 0 {
				current += spaceBufLen + wordBufLen
				spaceBuf.WriteTo(buf)
				spaceBuf.Reset()
				spaceBufLen = 0
				wordBuf.WriteTo(buf)
				wordBuf.Reset()
				wordBufLen = 0
			}

			spaceBuf.WriteRune(char)
			spaceBufLen++
		} else {
			wordBuf.WriteRune(char)
			wordBufLen++

			if current+wordBufLen+spaceBufLen > lim && wordBufLen < lim {
				buf.WriteRune('\n')
				current = 0
				spaceBuf.Reset()
				spaceBufLen = 0
			}
		}
	}

	if wordBuf.Len() == 0 {
		if current+spaceBufLen <= lim {
			spaceBuf.WriteTo(buf)
		}
	} else {
		spaceBuf.WriteTo(buf)
		wordBuf.WriteTo(buf)
	}

	return buf.String()
}
