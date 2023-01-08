# Date Time Group parser

Go module (with package `dtg`) for parsing and printing `time.Time` in Allied
Communication Publication (ACP) 121 NATO Date Time Group (DTG) format.

## Usage

Work in progress, more to come...

```go
package main

import (
	"fmt"
	"log"
	"time"

	"github.com/sa6mwa/dtg"
)

func main() {
	shortDTG := `151337`
	longDTG := `151337JAPR31`
	err := dtg.Validate(shortDTG)
	if err != nil {
		log.Fatal(err)
	}
	err = dtg.Validate(longDTG)
	if err != nil {
		log.Fatal(err)
	}
	sd, err := dtg.Parse(shortDTG)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("Short DTG", shortDTG, "is represented in full as", sd.String())
	fmt.Println("DTG", shortDTG, "time is", sd.Time.Format(time.UnixDate))

	ld, err := dtg.Parse(longDTG)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("Long DTG", longDTG, "is represented in full as", ld)
	fmt.Println("DTG", longDTG, "time is", ld.Time.Format(time.UnixDate))

	newDtg := &dtg.DTG{}
	newDtg.Time = time.Now()
	fmt.Println("DTG now in your time zone is", newDtg, "or", newDtg.Time.Format(time.UnixDate))
}
```
