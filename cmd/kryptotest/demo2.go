package main

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"sync"
	"time"

	"github.com/sa6mwa/krypto431/pkg/codec"
	"github.com/sa6mwa/krypto431/pkg/kenc"
	"github.com/sa6mwa/krypto431/pkg/keystore/testkeystore"
	"github.com/urfave/cli/v2"
)

/*
Encoded message: ZXAHXZCTQPNGQFNQTESTZPZPNGQTNRQZCFBDDCXAWIJFAEOEHANAKBKAKAAAAAAANEJEIEEFCAAAAAAAIAAAAAAAIAIACAAAAAAELGNCJNMAAAAAAABHDFCEHECAAKOMOBMOJAAAAAAAEGHEBENEBAAAALBIPALPMGBAFAAAAAAAJHAEIFJHDAAAAAOMDAAAAAOMDABMHGPKIGEAAAAAABKHEEFFIHEFDGPGGHEHHGBHCGFAAFAGBGJGOHECOEOEFFECAHGDDCODFCODBDADAPEHCKBAAAAAAEBEJEEEBFEBIFHGFIMEJAKAADAAIADHDBBHKPBPPMPLFEGEFLLAEFKGFEGACBDLFCPFIAGMONLDJOFBPPLLIKEFMGKHKEEJLHKEGJABOJNCFOGLGDLPJIOAGCGBMFOJKBBNNJGMCKADBBNLLIFDNAAAAAAAAEJEFEOEEKOECGAICWACWFNOJPKIKWAEF

Output message: ZYZDUMMYZYZZXAHXZCTQPNGQFNQTESTZPZPNGQTNRQZCFBDDCXAWIJFAEOEHANAKBKAKAAAAAAANEJEIEEFCAAAAAAAIAAAAAAAIAIACAAAAAAELGNCJNMAAAAAAABHDFCEHECAAKOMOBMOJAAAAAAAEGHEBENEBAAAALBIPALPMGBAFAAAAAAAJHAEIFJHDAAAAAOMDAAAAAOMDABMHGPKIGEAAAAAABKHEEFFIHEFDGPGGHEHHGBHCGFWYXZDUMMYZYXWAAFAGBGJGOHECOEOEFFECAHGDDCODFCODBDADAPEHCKBAAAAAAEBEJEEEBFEBIFHGFIMEJAKAADAAIADHDBBHKPBPPMPLFEGEFLLAEFKGFEGACBDLFCPFIAGMONLDJOFBPPLLIKEFMGKHKEEJLHKEGJABOJNCFOGLGDLPJIOAGCGBMFOJKBBNNJGMCKADBBNLLIFDNAAAAAAAAEJEFEOEEKOECGAICWACWFWYXZDUMMYZYXWNOJPKIKWAEF

ZYZDUMMYZYZZXAHXZCTQPNGQFNQTESTZPZPNGQTNRQZCFBDDCXAWIJFAEOEHANAKBKAKAAAAAAANEJEIEEFCAAAAAAAIAAAAAAAIAIACAAAAAAELGNCJNMAAAAAAABHDFCEHECAAKOMOBMOJAAAAAAAEGHEBENEBAAAALBIPALPMGBAFAAAAAAAJHAEIFJHDAAAAAOMDAAAAAOMDABMHGPKIGEAAAAAABKHEEFFIHEFDGPGGHEHHGBHCGFWYXZDUMMYZYXWAAFAGBGJGOHECOEOEFFECAHGDDCODFCODBDADAPEHCKBAAAAAAEBEJEEEBFEBIFHGFIMEJAKAADAAIADHDBBHKPBPPMPLFEGEFLLAEFKGFEGACBDLFCPFIAGMONLDJOFBPPLLIKEFMGKHKEEJLHKEGJABOJNCFOGLGDLPJIOAGCGBMFOJKBBNNJGMCKADBBNLLIFDNAAAAAAAAEJEFEOEEKOECGAICWACWFWYXZDUMMYZYXWNOJPKIKWAEFHeaders:
  CT: PNG
  FN: TEST.PNG
  TNR: 251332
CRC OK: true


*/

const img = "iVBORw0KGgoAAAANSUhEUgAAAAgAAAAICAIAAABLbSncAAAAAXNSR0IArs4c6QAAAARnQU1BAACxjwv8YQUAAAAJcEhZcwAADsMAAA7DAcdvqGQAAAAadEVYdFNvZnR3YXJlAFBhaW50Lk5FVCB2My41LjEwMPRyoQAAAEFJREFUGFdljEkKADAIA3MRevH/z7VGRbsEWmVGAhO1L1gGzts55R/7uKRcanpEm3pGkB6dJea2O/mOBiYcXpoR3ZbCoDEdu4U9AAAAAElFTkSuQmCC"

func runDemo2(c *cli.Context) error {
	// Dummy store is just used to print the key data
	// This is only possible since we are using a "non-random" random key
	// The testkeystore will always return the same key data
	store := testkeystore.New()
	//store := dummykey.New()
	//store.SetKeyChar('Z')
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
	msgA, _ := encoderA.NewMessage()
	msgB, _ := encoderB.NewMessage()
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
	fmt.Printf("Encoded message: %s\n\n", bufB.String())
	fmt.Printf("Output message: %s\n\n", bufA.String())

	decoder := codec.NewDecoder(decrypter)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for msg := range decoder.MsgC() {
			msgData, _ := ioutil.ReadAll(msg)
			fmt.Println("Headers:")
			for _, key := range msg.Header.Keys() {
				fmt.Printf("  %s: %s\n", key, msg.Header.Get(key))
			}
			fmt.Printf("CRC OK: %t\n", msg.VerifyChecksum())
			fmt.Println()
			fmt.Printf("Decoded message (hex coded): %s\n\n", hex.EncodeToString(msgData))
			fn := msg.Header.Get(codec.HeaderFilename)
			fmt.Println("Writing sample data to:", fn)
			f, err := os.Create(fn)
			if err != nil {
				log.Printf("Error creating output file: %v", err)
			}
			_, err = f.Write(msgData)
			if err != nil {
				log.Printf("Error writing to output file: %v", err)
			}
			err = f.Close()
			if err != nil {
				log.Printf("Error closing output file: %v", err)
			}
		}
	}()

	io.Copy(decoder, bufA)
	decoder.Close()
	wg.Wait()

	return nil
}
