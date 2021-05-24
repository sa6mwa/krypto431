package codec

import (
	"bytes"
	"fmt"
	"hash"
	"hash/crc32"
	"io"
	"strings"
)

type ReceivedMessage struct {
	Header        Header
	leftoverBytes []byte
	hash          hash.Hash
	section       Section
	sectionMode   bool
	msgBuf2       map[Section][]byte
	hexBuf        []byte
	hexMode       bool
	hasHeader     bool
	readC         chan []byte
	curReadBuf    []byte
	keyMode       bool
	keyBuf        []byte
	curKey        string
}

func newReceivedMessage() *ReceivedMessage {
	return &ReceivedMessage{
		Header:  Header{},
		msgBuf2: map[Section][]byte{},
		readC:   make(chan []byte),
		hash:    crc32.NewIEEE(),
	}
}

func (r *ReceivedMessage) HasHeader() bool {
	return r.hasHeader
}

func (r *ReceivedMessage) HasChecksum() bool {
	return len(r.msgBuf2[SectionChecksum]) > 0 && r.hash != nil
}

func (r *ReceivedMessage) VerifyChecksum() bool {
	return r.HasChecksum() &&
		bytes.Equal(r.hash.Sum(nil), r.msgBuf2[SectionChecksum])
}

func (r *ReceivedMessage) IsText() bool {
	if r.Header.Has(HeaderContentType) {
		dataType := strings.ToLower(r.Header.Get(HeaderContentType))
		return strings.HasPrefix(dataType, "text") ||
			dataType == "application/json" ||
			dataType == "application/xml" ||
			dataType == "json" ||
			dataType == "txt" ||
			dataType == "xml"
	}
	return true
}

func (r *ReceivedMessage) Read(p []byte) (int, error) {
	var ok bool
	if len(r.curReadBuf) == 0 {
		r.curReadBuf, ok = <-r.readC
		if !ok {
			return 0, io.EOF
		}
	}
	n := copy(p, r.curReadBuf)
	r.curReadBuf = r.curReadBuf[n:]
	return n, nil
}

func (r *ReceivedMessage) setSection(section Section) error {
	r.sectionMode = false
	r.section = section
	r.msgBuf2[section] = nil
	return nil
}

func (r *ReceivedMessage) closeSection(section Section) error {
	r.section = SectionDefault
	var err error
	switch section {
	case SectionChecksum:
	case SectionHeader:
		err = r.Header.Read(string(r.msgBuf2[section]))
		r.msgBuf2[section] = nil
		r.hasHeader = true
	case SectionDefault:
	}
	return err
}

func (r *ReceivedMessage) setSectionMode() {
	if r.section != SectionDefault {
		r.closeSection(r.section)
	} else {
		r.sectionMode = true
	}
}

func (r *ReceivedMessage) isSectionMode() bool {
	return r.sectionMode
}

func (r *ReceivedMessage) setHexMode() error {
	r.hexMode = !r.hexMode
	if !r.hexMode {
		r.flushHex()
	}
	return nil
}

func (r *ReceivedMessage) toggleKeyMode() bool {
	r.keyMode = !r.keyMode
	if !r.keyMode {
		r.curKey = string(r.keyBuf)
		r.keyBuf = nil
	}
	return r.keyMode
}

func (r *ReceivedMessage) getCurKey() string {
	return r.curKey
}

func (r *ReceivedMessage) flush() error {
	if len(r.msgBuf2[SectionDefault]) > 0 {
		b := r.msgBuf2[SectionDefault]
		if r.hash != nil {
			r.hash.Write(b)
		}
		r.readC <- b
		r.msgBuf2[SectionDefault] = nil
	}
	return r.flushHex()
}

func (r *ReceivedMessage) flushHex() error {
	bufLen := len(r.hexBuf)
	if bufLen == 0 {
		return nil
	}
	bytesToDecode := int(float64(bufLen) / 2)
	if bufLen > bytesToDecode*2 {
		r.leftoverBytes = r.hexBuf[bufLen-1:]
	} else {
		r.leftoverBytes = nil
	}
	decBMsg, err := decodeBin(r.hexBuf[:bytesToDecode*2])
	if err != nil {
		return fmt.Errorf("error decoding hex data: %w", err)
	}
	r.append(decBMsg...)
	r.hexBuf = nil
	return nil
}

func (r *ReceivedMessage) append(b ...byte) {
	if b == nil {
		return
	}
	if r.keyMode {
		r.keyBuf = append(r.keyBuf, b...)
		return
	}
	r.msgBuf2[r.section] = append(r.msgBuf2[r.section], b...)
}

func (r *ReceivedMessage) appendHex(b ...byte) {
	if len(r.leftoverBytes) > 0 {
		r.hexBuf = append(r.hexBuf, r.leftoverBytes...)
		r.leftoverBytes = nil
	}
	r.hexBuf = append(r.hexBuf, b...)
}

func (r *ReceivedMessage) close() error {
	defer close(r.readC)
	err := r.closeSection(r.section)
	if err != nil {
		return err
	}
	return r.flush()
}
