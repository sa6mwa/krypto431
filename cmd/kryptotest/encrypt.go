package main

import (
	"bytes"
	"fmt"
	"log"

	"github.com/sa6mwa/krypto431/pkg/codec"
	"github.com/sa6mwa/krypto431/pkg/kenc"
	"github.com/sa6mwa/krypto431/pkg/keystore/keydir"
	"github.com/urfave/cli/v2"
)

func runEncrypt(c *cli.Context) error {
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

	encrypter := kenc.NewEncrypter(store)
	defer func() {
		err := encrypter.Close()
		if err != nil {
			log.Printf("Error closing decrypter: %v", err)
		}
	}()

	buf := bytes.NewBuffer(nil)
	encoder := codec.NewEncoder(buf, encrypter)

	msgEncoder, _ := encoder.NewMessage()
	err = msgEncoder.WriteString(msg)
	if err != nil {
		return fmt.Errorf("error writing message: %w", err)
	}
	err = msgEncoder.Close()
	if err != nil {
		return fmt.Errorf("error closing message: %w", err)
	}

	err = encoder.Close()
	if err != nil {
		return fmt.Errorf("error closing decoder: %w", err)
	}

	fmt.Println(buf.String())

	return nil
}
