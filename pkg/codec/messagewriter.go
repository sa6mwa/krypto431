package codec

import (
	"bytes"
	"fmt"
	"hash"
	"hash/crc32"
	"strings"
)

type MessageWriter struct {
	Header       Header
	headerSent   bool
	filename     string
	contentType  string
	checksum     hash.Hash
	encoder      *Encoder
	noEndMarkers bool
}

func (m *MessageWriter) WithCRC32() *MessageWriter {
	m.checksum = crc32.NewIEEE()
	return m
}

func (m *MessageWriter) WithFilename(name string) *MessageWriter {
	m.filename = name
	return m
}

func (m *MessageWriter) WithContentType(contentType string) *MessageWriter {
	m.contentType = strings.ToUpper(contentType)
	return m
}

func (m *MessageWriter) WriteString(str string) error {
	_, err := m.Write([]byte(str))
	return err
}

// Write implements io.Writer
func (m *MessageWriter) Write(p []byte) (int, error) {
	var err error
	sendAsBytes := false
	if !m.headerSent {
		sendAsBytes, err = m.writeHeader()
		if err != nil {
			return 0, fmt.Errorf("error writing header: %w", err)
		}
		m.headerSent = true
	}
	if m.checksum != nil {
		_, err := m.checksum.Write(p)
		if err != nil {
			return 0, fmt.Errorf("error writing checksum: %w", err)
		}
	}
	if sendAsBytes {
		err = m.encoder.encodeBytes(p)
	} else {
		err = m.encoder.encodeString(string(p))
	}
	if err != nil {
		return 0, err
	}
	return len(p), nil
}

// Close implements io.Closer
func (m *MessageWriter) Close() error {
	var checkerData []byte
	if m.checksum != nil {
		checkerData = m.checksum.Sum(nil)
	}
	var err error
	if checkerData != nil {
		err = m.encoder.setSection(SectionChecksum)
		if err != nil {
			return err
		}
		err = m.encoder.encodeBytes(checkerData)
		if err != nil {
			return err
		}
		err = m.encoder.setSection(SectionDefault)
		if err != nil {
			return err
		}
	}
	if !m.noEndMarkers {
		return m.encoder.endOfMessage()
	}
	return nil
}

func (m *MessageWriter) writeHeader() (bool, error) {
	sendAsBytes := false
	headerBuf := bytes.NewBuffer(nil)
	if m.filename != "" {
		m.Header.Set(HeaderFilename, m.filename)
	}
	if m.contentType != "" {
		m.Header.Set(HeaderContentType, m.contentType)
		sendAsBytes = !contentTypeIsText(m.contentType)
	}
	err := m.Header.Write(headerBuf)
	if err != nil {
		return sendAsBytes, err
	}
	if headerBuf.Len() == 0 {
		return sendAsBytes, nil
	}
	err = m.encoder.setSection(SectionHeader)
	if err != nil {
		return sendAsBytes, err
	}
	err = m.encoder.encodeString(headerBuf.String())
	if err != nil {
		return sendAsBytes, err
	}
	err = m.encoder.setSection(SectionDefault)
	if err != nil {
		return sendAsBytes, err
	}
	return sendAsBytes, nil
}
