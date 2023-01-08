package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"sync"

	"github.com/sa6mwa/krypto431/pkg/codec"
	"github.com/sa6mwa/krypto431/pkg/kenc"
	"github.com/sa6mwa/krypto431/pkg/keystore/keydir"
	"github.com/urfave/cli/v2"
)

func runDecrypt(c *cli.Context) error {
	msg := c.Args().First()
	if msg == "" {
		return fmt.Errorf("message argument missing")
	}
	keyDir := c.String("key-dir")

	store := keydir.New(keyDir)
	err := store.Open()
	if err != nil {
		return fmt.Errorf("error opening key dir: %w", err)
	}
	defer func() {
		err := store.Close()
		if err != nil {
			log.Printf("Error closing key store: %v", err)
		}
	}()

	decrypter := kenc.NewDectypter(store)
	defer func() {
		err := decrypter.Close()
		if err != nil {
			log.Printf("Error closing decrypter: %v", err)
		}
	}()

	decoder := codec.NewDecoder(decrypter)

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for inMsg := range decoder.MsgC() {
			buf, err := ioutil.ReadAll(inMsg)
			if err != nil {
				log.Printf("Error reading message: %v", err)
			}
			if inMsg.HasChecksum() {
				fmt.Printf("Checksum OK: %t\n", inMsg.VerifyChecksum())
			}
			fmt.Printf("Message: %s\n", string(buf))
			fmt.Println()
		}
	}()

	_, err = decoder.Write([]byte(msg))
	if err != nil {
		return fmt.Errorf("error writing to decoder: %w", err)
	}

	err = decoder.Close()
	if err != nil {
		return fmt.Errorf("error closing decoder: %w", err)
	}
	wg.Wait()

	return nil
}
