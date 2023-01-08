package krand

import (
	"fmt"
	"io"
)

const moduloMr = 26

func Generate(rng io.Reader, out io.Writer, size int64) (int64, error) {
	const bufSize int64 = 1024
	buf := make([]byte, bufSize)
	var sizeWritten int64
	for sizeWritten < size {
		n, err := rng.Read(buf)
		if err != nil {
			return sizeWritten, fmt.Errorf("error reading data from random number source: %w", err)
		}
		for i := 0; i < n; i++ {
			buf[i] = byte(int(buf[i])%moduloMr) + byte('A')
		}
		sizeToWrite := bufSize
		if size-sizeWritten < sizeToWrite {
			sizeToWrite = size - sizeWritten
		}
		n, err = out.Write(buf[0:sizeToWrite])
		if err != nil {
			return sizeWritten, fmt.Errorf("error writing data to output: %w", err)
		}
		sizeWritten += int64(n)
	}
	return sizeWritten, nil
}
