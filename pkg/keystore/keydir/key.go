package keydir

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

type Key struct {
	dir       string
	name      string
	len       int64
	bytesLeft int64
	f         *os.File
}

var BOMs = [][]byte{
	// From Wikipedia
	{0xEF, 0xBB, 0xBF},       // UTF-8
	{0xFE, 0xFF},             // UTF-16 (BE)
	{0xFF, 0xFE},             // UTF-16 (LE)
	{0x00, 0x00, 0xFE, 0xFF}, // UTF-32 (BE)
	{0xFF, 0xFE, 0x00, 0x00}, // UTF-32 (LE)
	{0x2B, 0x2F, 0x76},       // UTF-7
	{0xF7, 0x64, 0x4C},       // UTF-1
	{0xDD, 0x73, 0x66, 0x73}, // UTF-EBCDIC
	{0x0E, 0xFE, 0xFF},       // SCSU
	{0xFB, 0xEE, 0x28},       // BOCU-1
	{0x84, 0x31, 0x95, 0x33}, // GB-18030
}

func (k *Key) Name() string {
	return k.name
}

func (k *Key) BytesLeft() int {
	return int(k.bytesLeft)
}

func (k *Key) Read(p []byte) (int, error) {
	n, err := k.f.Read(p)
	k.bytesLeft -= int64(n)
	return n, err
}

func (k *Key) open() error {
	var err error
	fn := filepath.Join(k.dir, k.name+keyExt)
	stat, err := os.Stat(fn)
	if err != nil {
		return fmt.Errorf("stat error: %w", err)
	}
	if !stat.Mode().IsRegular() {
		return fmt.Errorf("not a regular file")
	}
	k.len = stat.Size()
	k.bytesLeft = k.len
	k.f, err = os.OpenFile(fn, os.O_RDWR, 0)
	if err != nil {
		return fmt.Errorf("error opening key: %w", err)
	}
	// Strip byte order mark (BOM) if it exists
	// BOms can be a problem on Widows, so we strip them
	buf := make([]byte, 4)
	_, err = io.ReadAtLeast(k.f, buf, len(buf))
	if err != nil {
		return fmt.Errorf("error reading from key file '%s': %w", k.name, err)
	}
	skipBytes := 0
	for _, bom := range BOMs {
		if bytes.Equal(bom, buf[0:len(bom)]) {
			skipBytes = len(bom)
			break
		}
	}
	_, err = k.f.Seek(int64(skipBytes), io.SeekStart)
	if err != nil {
		return fmt.Errorf("error seeking key position '%d': %w", skipBytes, err)
	}
	return err
}

func (k *Key) close() error {
	_, err := k.f.Seek(0, io.SeekStart)
	if err != nil {
		return fmt.Errorf("error seeking to key start: %w", err)
	} else {
		const bufLen = 1024
		zeroBuf := make([]byte, bufLen)
		bytesLeft := k.len
		for bytesLeft > 0 {
			bytesToWrite := bytesLeft
			if bytesToWrite > bufLen {
				bytesToWrite = bufLen
			}
			n, err := k.f.Write(zeroBuf[:bytesToWrite])
			if err != nil {
				return fmt.Errorf("error writing zero data to key: %w", err)
			}
			bytesLeft -= int64(n)
		}
	}
	err = k.f.Close()
	if err != nil {
		return fmt.Errorf("error closing key: %w", err)
	}
	k.f = nil
	k.bytesLeft = 0
	k.len = 0
	err = os.Remove(filepath.Join(k.dir, k.name+keyExt))
	if err != nil {
		return fmt.Errorf("error removing used key: %w", err)
	}
	return nil
}
