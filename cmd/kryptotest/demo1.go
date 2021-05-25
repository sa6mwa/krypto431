package main

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"sync"

	"github.com/sa6mwa/krypto431/pkg/codec"
	"github.com/sa6mwa/krypto431/pkg/kenc"
	"github.com/sa6mwa/krypto431/pkg/keystore/testkeystore"
	"github.com/urfave/cli/v2"
)

func runDemo1(c *cli.Context) error {
	// Dummy store is just used to print the key data
	// This is only possible since we are using a "non-random" random key
	// The testkeystore will always return the same key data
	dummyStore := testkeystore.New()
	defer dummyStore.Close()
	store := testkeystore.New()
	defer store.Close()

	encrypter := kenc.NewEncrypter(store)
	defer encrypter.Close()
	decrypter := kenc.NewDectypter(store)
	defer decrypter.Close()

	bufA := bytes.NewBuffer(nil)
	bufB := bytes.NewBuffer(nil)

	// The encoder will write output data to the buffer
	encoderA := codec.NewEncoder(bufA, encrypter)
	encoderB := codec.NewEncoder(bufB, nil)
	msgA, _ := encoderA.NewMessage()
	msgB, _ := encoderB.NewMessage()
	inMsg := "THIS IS A TEST MESSAGE"
	msgA.WriteString(inMsg)
	msgB.WriteString(inMsg)
	msgA.Close()
	msgB.Close()
	encoderA.Close()
	encoderB.Close()
	fmt.Printf("Input message:        %s\n", inMsg)
	fmt.Printf("Encoded message:      %s\n", bufB.String())
	fmt.Printf("Output message:  %s\n", bufA.String())
	key, _ := dummyStore.NextKey()
	keyBytes := make([]byte, bufB.Len()+1)
	io.ReadAtLeast(key, keyBytes, len(keyBytes))
	fmt.Printf("Key used:            %s\n", string(keyBytes))

	decoder := codec.NewDecoder(decrypter)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for msg := range decoder.MsgC() {
			msgData, err := io.ReadAll(msg)
			if err != nil {
				log.Printf("Read error: %v", err)
			}
			fmt.Printf("Decoded message:      %s\n", string(msgData))
		}
	}()

	_, err := io.Copy(decoder, bufA)
	if err != nil {
		return err
	}
	decoder.Close()
	wg.Wait()

	/*encoder = codec.NewEncoder(buf, encrypter)
	msg = encoder.NewMessage()
	msg.WithCRC32()
	msg.WithContentType("PNG")
	msg.WithFilename("TEST.PNG")
	msg.Header.Set(codec.HeaderTimeNr, time.Now().Format("021504"))
	msg.Close()
	encoder.Close()*/

	return nil
}
