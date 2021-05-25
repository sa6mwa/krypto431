package main

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"io/ioutil"
	"sync"
	"time"

	"github.com/sa6mwa/krypto431/pkg/codec"
	"github.com/sa6mwa/krypto431/pkg/kenc"
	"github.com/sa6mwa/krypto431/pkg/keystore/keydummy"
	"github.com/urfave/cli/v2"
)

const img = "iVBORw0KGgoAAAANSUhEUgAAAAgAAAAICAIAAABLbSncAAAAAXNSR0IArs4c6QAAAARnQU1BAACxjwv8YQUAAAAJcEhZcwAADsMAAA7DAcdvqGQAAAAadEVYdFNvZnR3YXJlAFBhaW50Lk5FVCB2My41LjEwMPRyoQAAAEFJREFUGFdljEkKADAIA3MRevH/z7VGRbsEWmVGAhO1L1gGzts55R/7uKRcanpEm3pGkB6dJea2O/mOBiYcXpoR3ZbCoDEdu4U9AAAAAElFTkSuQmCC"

func runDemo2(c *cli.Context) error {
	// Dummy store is just used to print the key data
	// This is only possible since we are using a "non-random" random key
	// The testkeystore will always return the same key data
	store := keydummy.New()
	defer store.Close()

	encrypter := kenc.NewEncrypter(store)
	defer encrypter.Close()
	decrypter := kenc.NewDectypter(store)
	defer decrypter.Close()

	bufA := bytes.NewBuffer(nil)
	bufB := bytes.NewBuffer(nil)

	imgBytes, _ := base64.StdEncoding.DecodeString(img)

	// The encoder will write output data to the buffer
	encoderA := codec.NewEncoder(bufA, encrypter)
	encoderB := codec.NewEncoder(bufB, nil)
	msgA := encoderA.NewMessage()
	msgB := encoderB.NewMessage()
	msgA.WithCRC32()
	msgA.WithContentType("PNG")
	msgA.WithFilename("TEST.PNG")
	msgA.Header.Set(codec.HeaderTimeNr, time.Now().Format("021504"))
	msgB.WithCRC32()
	msgB.WithContentType("PNG")
	msgB.WithFilename("TEST.PNG")
	msgB.Header.Set(codec.HeaderTimeNr, time.Now().Format("021504"))
	msgA.Write(imgBytes)
	msgB.Write(imgBytes)
	msgA.Close()
	msgB.Close()
	encoderA.Close()
	encoderB.Close()
	fmt.Printf("Encoded message: %s\n", bufB.String())
	fmt.Printf("Output message: %s\n", bufA.String())

	decoder := codec.NewDecoder(decrypter)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for msg := range decoder.MsgC() {
			msgData, _ := ioutil.ReadAll(msg)
			fmt.Println("Headers:")
			for _, key := range msg.Header.Keys() {
				fmt.Printf("  %s: %s", key, msg.Header.Get(key))
			}
			fmt.Printf("Decoded message: %s\n", string(msgData))
		}
	}()

	io.Copy(decoder, bufA)
	decoder.Close()
	wg.Wait()

	return nil
}
