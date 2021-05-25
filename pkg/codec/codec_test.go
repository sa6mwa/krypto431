package codec

import (
	"bytes"
	"io"
	"io/ioutil"
	"sync"
	"testing"

	"github.com/sa6mwa/krypto431/pkg/kenc"
	"github.com/sa6mwa/krypto431/pkg/keystore/dummykey"
	"github.com/stretchr/testify/assert"
)

func TestCodec(t *testing.T) {
	//decStore := keydir.New("C:\\dev\\kryptotest\\keys_dec")
	decStore := dummykey.New()
	err := decStore.Open()
	assert.NoError(t, err)
	defer func() {
		err := decStore.Close()
		assert.NoError(t, err)
	}()

	decrypter := kenc.NewDectypter(decStore)
	defer func() {
		err := decrypter.Close()
		assert.NoError(t, err)
	}()
	dec := NewDecoder(decrypter)

	encMessages := []string{
		"TEST MESSAGE",
		"Test Message!",
		"åäöÅÄÖ",
		"1024 = 1KiB",
		"!\"#¤%&/()=?",
		"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
	}

	//encStore := keydir.New("C:\\dev\\kryptotest\\keys_enc")
	encStore := dummykey.New()
	err = encStore.Open()
	assert.NoError(t, err)
	defer func() {
		err := encStore.Close()
		assert.NoError(t, err)
	}()
	encrypter := kenc.NewEncrypter(encStore)

	encBuf := bytes.NewBuffer(nil)
	enc := NewEncoder(encBuf, encrypter)

	var decMessages []string
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for msg := range dec.MsgC() {
			buf, err := ioutil.ReadAll(msg)
			assert.NoError(t, err)
			if msg.HasChecksum() {
				ok := msg.VerifyChecksum()
				assert.True(t, ok)
			}
			decMessages = append(decMessages, string(buf))
		}
	}()

	for _, encMessage := range encMessages {
		msg := enc.NewMessage()
		msg.WithCRC32()
		err := msg.WriteString(encMessage)
		assert.NoError(t, err)
		err = msg.Close()
		assert.NoError(t, err)
	}
	err = enc.Close()
	assert.NoError(t, err)

	bufLen := len(encBuf.Bytes())
	//fmt.Println("BUF:", encBuf.String())
	n, err := io.Copy(dec, encBuf)
	assert.NoError(t, err)
	assert.Equal(t, bufLen, int(n))
	err = dec.Close()
	assert.NoError(t, err)

	wg.Wait()

	for i, decMessage := range decMessages {
		//fmt.Printf("%d: '%s'\n", i, decMessage)
		assert.Equal(t, encMessages[i], decMessage)
	}
	//t.Fail()
}
