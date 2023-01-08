// Blox is a Go package to block-paste text in a character raster buffer. Text
// is pasted and positioned via X/Y coordinates on a canvas which can be printed
// as-is or delimited by line breaks at column-width. Trailing spaces and
// trailing empty lines can be trimmed from the output and/or before printing
// the canvas.
//
// The example below illustrates basic usage. See the PutText functions
// for more examples.
//
//	package main
//
//	import (
//	  "fmt"
//
//	  "github.com/sa6mwa/blox"
//	)
//
//	func main() {
//	  b := blox.New().Trim().SetColumnsAndRows(80, 24)
//
//	  text := "ABCDE FGHIJ KLMNO" + blox.LineBreak
//	  text += "PQRST UVWXY ZABCD" + blox.LineBreak
//
//	  heading := "CRYPTO" + blox.LineBreak
//	  heading += "GROUPS"
//
//	  str := b.PutText(heading).DrawHorizontalLine(0, 6).DrawVerticalLine(0, 1, ':').
//	    PutChar('+').MoveDown().MoveX(0).PutText(text).
//	    Move(9, 0).PutText(text).Join(blox.LineBreak)
//
//	  strEndingInNewLine := b.String()
//
//	  fmt.Println(str)
//	  fmt.Println("--")
//	  fmt.Print(strEndingInNewLine)
//	}
//
// Output
//
//	CRYPTO : ABCDE FGHIJ KLMNO
//	GROUPS : PQRST UVWXY ZABCD
//	-------+
//	ABCDE FGHIJ KLMNO
//	PQRST UVWXY ZABCD
//	--
//	CRYPTO : ABCDE FGHIJ KLMNO
//	GROUPS : PQRST UVWXY ZABCD
//	-------+
//	ABCDE FGHIJ KLMNO
//	PQRST UVWXY ZABCD
package blox
