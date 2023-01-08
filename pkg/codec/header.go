package codec

import (
	"fmt"
	"io"
	"math"
	"sort"
	"strings"
)

// Predefined standard headers
const (
	// HeaderFilename, Filename of the data, if applicable:
	// Use hex mode to encode in UTF-8
	HeaderFilename = "FN"
	// HeaderContentLength, length of the data/message in bytes before encoding
	HeaderContentLength = "CL"
	// HeaderContentType, data type of the data, usually a mime type, but can
	// also be a short file extension (JPG/TXT/etc).
	// Defaults to application/octet-stream (generic 8 bit data) if missing
	HeaderContentType = "CT"
	// HeaderContentEncoding defines any special encoding scheme used.
	// For example gzip
	HeaderContentEncoding = "CE"
	// HeaderTimestamp is a timestamp at which the message was orginated
	// Format is ISO 8601. Example: 2021-05-24T13:43:20Z
	// The time part can be excluded if needed
	HeaderTimestamp = "TS"
	// HeaderTimeNr is a simplified timestamp at which the message was orginated
	// Format is NNHHMM[Z] where NN is the day, HH is hour and MM is minute,
	// Z is an optional time zone code
	// If the time number is in the switch between daylight savings, use odd
	// numbers for the first hour and even numbers for the second time the
	// same hours occurres
	HeaderTimeNr = "TNR"
	// HeaderDateTimeGroup is a simplified timestamp at witch the message was orginated.
	// Format is DD HHMMZ MON YY
	// Example 1: 09 1630Z JUL 11 represents (Jul) 09 16:30 Jul 2011 (UTC).
	// Example 2: 22 0301Z May 21 represents (May) 22 03:01, May 2021 (UTC).
	HeaderDateTimeGroup = "DTG"
	// HeaderTo is a comma separated list of recipients (who should receive the message)
	HeaderTo = "TO"
	// HeaderFrom is a comma separated list of senders (who sent the message)
	HeaderFrom = "DE"
	// HeaderCc is a comma separated list of carbon copy recipients
	HeaderCc = "CC"
	// HeaderBcc is a comma separated list of blind carbon copy recipients
	HeaderBcc = "BCC"
	// HeaderPart defines that this message is part P of N parts.
	// Format is: P,N
	HeaderPart = "PART"
	// HeaderLanguage identifies the language used in this message
	// By convention use the english language name
	HeaderLanguage = "LANG"
	// HeaderID is a (preferably) unique ID for this message
	HeaderID = "ID"
)

type Header map[string]string

// Set sets the header entry
func (h Header) Set(key, value string) {
	h[key] = value
}

// Get gets the value associated with the given key
func (h Header) Get(key string) string {
	return h[key]
}

// has reports whether h has the provided key defined
func (h Header) Has(key string) bool {
	_, ok := h[key]
	return ok
}

// Del deletes the value associated with key
func (h Header) Del(key string) {
	delete(h, key)
}

func (h Header) Keys() []string {
	var keys []string
	for key := range h {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

// Clone returns a copy of h or nil if h is nil.
func (h Header) Clone() Header {
	if h == nil {
		return nil
	}
	h2 := make(Header, len(h))
	for k, v := range h {
		h2[k] = v
	}
	return h2
}

// Write writes a header in wire format
func (h Header) Write(w io.Writer) error {
	keys := []string{}
	for key := range h {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool {
		return keys[i] < keys[j]
	})
	headers := make([]string, len(keys))
	for i, key := range keys {
		headers[i] = key + " " + h[key]
	}
	_, err := fmt.Fprint(w, strings.Join(headers, " "))
	if err != nil {
		return fmt.Errorf("error writing headers: %w", err)
	}
	return nil
}

// Read reads a header in wire format
func (h Header) Read(str string) error {
	parts := strings.Split(str, " ")
	pairCount := int(math.Floor(float64(len(parts)) / 2))
	for i := 0; i < pairCount; i++ {
		key := parts[i*2]
		value := parts[(i*2)+1]
		h[key] = value
	}
	return nil
}
