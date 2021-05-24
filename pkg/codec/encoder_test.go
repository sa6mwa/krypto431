package codec

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/sa6mwa/krypto431/pkg/kenc"
	"github.com/sa6mwa/krypto431/pkg/keystore/testkeystore"
	"github.com/stretchr/testify/assert"
)

var sampleJSON = `
{
    "glossary": {
        "title": "example glossary",
		"GlossDiv": {
            "title": "S",
			"GlossList": {
                "GlossEntry": {
                    "ID": "SGML",
					"SortAs": "SGML",
					"GlossTerm": "Standard Generalized Markup Language",
					"Acronym": "SGML",
					"Abbrev": "ISO 8879:1986",
					"GlossDef": {
                        "para": "A meta-markup language, used to create markup languages such as DocBook.",
						"GlossSeeAlso": ["GML", "XML"]
                    },
					"GlossSee": "markup"
                }
            }
        }
    }
}`

func TestEncoder(t *testing.T) {
	buf := bytes.NewBuffer(nil)
	store := testkeystore.New()
	err := store.Open()
	assert.NoError(t, err)
	defer func() {
		err := store.Close()
		assert.NoError(t, err)
	}()
	encrypter := kenc.NewEncrypter(store)
	defer func() {
		err := encrypter.Close()
		assert.NoError(t, err)
	}()
	enc := NewEncoder(buf, encrypter)

	mw := enc.NewMessage()
	mw.WithCRC32()
	err = mw.WriteString("TEST MESSAGE")
	assert.NoError(t, err)
	err = mw.Close()
	assert.NoError(t, err)

	mw = enc.NewMessage()
	err = mw.WriteString("PLAIN MESSAGE")
	assert.NoError(t, err)
	err = mw.Close()
	assert.NoError(t, err)

	mw = enc.NewMessage()
	mw.WithContentType("APPLICATION/JSON")
	mw.WithFilename("TEST.JSON")
	mw.WithCRC32()
	_, err = mw.Write([]byte(sampleJSON))
	assert.NoError(t, err)
	err = mw.Close()
	assert.NoError(t, err)

	enc.Close()
	fmt.Println(buf.String())
}

type debugWriter struct {
	b *bytes.Buffer
}

func (d *debugWriter) Write(p []byte) (int, error) {
	fmt.Println("WRITE", string(p))
	return d.b.Write(p)
}
