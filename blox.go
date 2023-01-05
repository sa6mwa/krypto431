package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

var (
	InitialCanvasCapacity  int = 80 * 24
	InitialCanvasColumns   int = 0
	InitialCanvasRows      int = 0
	InitialCursorPositionX int = 0
	InitialCursorPositionY int = 0
	InitialLineSpacing int = 1
)

type Blox struct {
	Columns int // X
	Rows    int // Y
	Cursor  CursorPosition
	LineSpacing int
	Canvas  []rune
}

type CursorPosition struct {
	X int // Column
	Y int // Row
}

func (b *Blox) index() int {
	if b.Cursor.X*b.Cursor.Y >= len(b.Canvas) {
		if len(b.Canvas) > 0 {
			return len(b.Canvas) - 1
		} else {
			return 0
		}
	}
	return b.Cursor.Y*b.Columns + b.Cursor.X
}

func New() *Blox {
	b := Blox{
		Columns: InitialCanvasColumns,
		Rows:    InitialCanvasRows,
		LineSpacing: InitialLineSpacing,
		Canvas:  make([]rune, 0, InitialCanvasCapacity),
	}
	b.ResizeCanvas().MoveCursor(InitialCursorPositionX, InitialCursorPositionY)
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
	return b
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
	b.LineSpacing(n)
	return b
}

// MoveCursor to a column/row position on the canvas where x is column and y is
// row, upp left hand corner is 0,0.
func (b *Blox) MoveCursor(x int, y int) *Blox {
	if x >= b.Columns {
		if b.Columns > 0 {
			b.Cursor.X = b.Columns - 1
		} else {
			b.Cursor.X = 0
		}
	} else {
		b.Cursor.X = x
	}
	if y >= b.Rows {
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

func (b *Blox) MoveCursorRight(n ...int) *Blox {
	step := 1
	if len(n) > 0 {
		if n[0] > step {
			step = n[0]
		}
	}
	return b.MoveCursor(b.Cursor.X+step, b.Cursor.Y)
}

func (b *Blox) PutLine(runes []rune) *Blox {
	for _, r := range runes {
		if b.Cursor.X < b.Columns {
			switch {
			case r == '\n', r == '\r':
				continue
			}
			b.Canvas[b.index()] = r
			b.MoveCursorRight()
		}
	}
	return b
}

func (b *Blox) PutLines(lines ...string) *Blox {
	if b.Rows == 0 || b.Columns == 0 {
		return b
	}
	originX := b.Cursor.X
	//originY := b.Cursor.Y
	for _, line := range lines {
		b.PutLine([]rune(line))
		b.MoveCursor(originX, b.Cursor.Y+b.LineSpacing)
	}
	return b
}

func (b *Blox) PutText(text string) *Blox {
	var lines []string
	s := bufio.NewScanner(strings.NewReader(text))
	for s.Scan() {
		lines = append(lines, s.Text())
	}
// continue here
	return b
}

func (b *Blox) FprintCanvas(*os.File) *Blox {
	for b.
	return b
}

func (b *Blox) PrintCanvas() *Blox {
	return FprintCanvas(os.Stdout)
}


// The main thing is the main thing...
func main() {

	b := New().SetColumnsAndRows(80, 24)
	fmt.Printf("%+v\n", b)

}
