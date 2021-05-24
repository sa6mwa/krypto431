package codec

import (
	"fmt"
	"io"
	"math"
	"sort"
	"strings"
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
