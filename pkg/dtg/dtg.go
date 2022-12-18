// dtg - a NATO Date Time Group parser (C) 2022 SA6MWA Michel
//
// Format according to Allied Communication Publication, ACP 121: COMMUNICATION
// INSTRUCTIONS GENERAL

package dtg

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
)

var (
	dtgRe         *regexp.Regexp = regexp.MustCompile(`^([0-9]{2})([0-9]{2})([0-9]{2})([A-Z]{0,1})(JAN|FEB|MAR|APR|MAY|JUN|JUL|AUG|SEP|OCT|NOV|DEC){0,1}([0-9]{2}){0,1}$`)
	ErrInvalidDTG error          = errors.New("invalid DTG format (minimally ddHHMM to complete ddHHMMZmmmYY)")
)

const (
	_ = iota
	dtgSubMatchDay
	dtgSubMatchHour
	dtgSubMatchMinute
	dtgSubMatchTimeZone
	dtgSubMatchMonth
	dtgSubMatchYear
)

const (
	numericTimeZoneLayout string = "-0700"
	expandedDtgLayout     string = `021504-0700Jan06`
	monthLayout           string = `Jan`
	yearLayout            string = `06`
)

type DTG struct {
	time.Time
}

// String returns a NATO ACP 121 Date Time Group of the DTG Time field.
func (dtg DTG) String() string {
	_, offset := dtg.Time.Zone()
	hours := offset / (60 * 60)
	letter := rune('J')
	if hours == 0 {
		letter = 'Z'
	} else if hours >= 1 && hours <= 9 {
		letter = 'A'
		letter += rune(hours - 1)
	} else if hours >= 10 && hours <= 12 {
		letter = 'A'
		letter += rune(hours)
	} else if hours >= -12 && hours <= -1 {
		letter = 'Z'
		letter += rune(hours)
	}
	return dtg.Time.Format(`021504`) + string(letter) + strings.ToUpper(dtg.Time.Format(`Jan06`))
}

// Parse transforms a NATO (ACP 121 Communication Instructions General) Date
// Time Group into a time.Time object via the DTG struct. The String() function
// of the DTG object reproduces a full Date Time Group from the time.Time object.
func Parse(dtgString string) (dtg DTG, err error) {
	dtgString = strings.ToUpper(strings.TrimSpace(dtgString))
	matches := dtgRe.FindAllStringSubmatch(dtgString, 1)
	if len(matches) != 1 || len(matches[0]) != 7 {
		return dtg, ErrInvalidDTG
	}
	match := matches[0]
	numericTimeZone := GetNumericTimezone(match[dtgSubMatchTimeZone])
	if len(match[dtgSubMatchMonth]) < 3 {
		match[dtgSubMatchMonth] = strings.ToUpper(time.Now().In(numericTimeZone).Format(monthLayout))
		fmt.Println(match[dtgSubMatchMonth])
	}
	if len(match[dtgSubMatchYear]) < 2 {
		match[dtgSubMatchYear] = time.Now().In(numericTimeZone).Format(yearLayout)
	}
	expandedDtg := match[dtgSubMatchDay] + match[dtgSubMatchHour] +
		match[dtgSubMatchMinute] + numericTimeZone.String() +
		match[dtgSubMatchMonth] + match[dtgSubMatchYear]

	dtg.Time, err = time.ParseInLocation(expandedDtgLayout, expandedDtg, numericTimeZone)
	if err != nil {
		return dtg, err
	}
	return dtg, nil
}

// Return a time.Location with the numeric time zone representation (e.g +0100
// or -1100) of an ACP 121 time zone letter (A-Z). Name field will be the
// numeric time zone (to parse with -0700). There is a String() function in
// time.Location to extract the numeric time zone as name is non-exported. Will
// always return local numeric time zone in case of an error.
// UTC-12: Y (e.g., Fiji)
// UTC-11: X (American Samoa)
// UTC-10: W (Honolulu, HI)
// UTC-9: V (Juneau, AK)
// UTC-8: U (PST, Los Angeles, CA)
// UTC-7: T (MST, Denver, CO)
// UTC-6: S (CST, Dallas, TX)
// UTC-5: R (EST, New York, NY)
// UTC-4: Q (Halifax, Nova Scotia)
// UTC-3: P (Buenos Aires, Argentina)
// UTC-2: O (Godthab, Greenland)
// UTC-1: N (Azores)
// UTC+-0: Z (Zulu time)
// UTC+1: A (France)
// UTC+2: B (Athens, Greece)
// UTC+3: C (Arab Standard Time, Iraq, Bahrain, Kuwait, Saudi Arabia, Yemen, Qatar)
// UTC+4: D (Used for Moscow, Russia, and Afghanistan, however, Afghanistan is technically +4:30 from UTC)
// UTC+5: E (Pakistan, Kazakhstan, Tajikistan, Uzbekistan, and Turkmenistan)
// UTC+6: F (Bangladesh)
// UTC+7: G (Thailand)
// UTC+8: H (Beijing, China)
// UTC+9: I (Tokyo, Japan)
// UTC+10: K (Brisbane, Australia)
// UTC+11: L (Sydney, Australia)
// UTC+12: M (Wellington, New Zealand)
func GetNumericTimezone(dtgTimeZoneLetter string) *time.Location {
	dtgTimeZoneLetter = strings.ToUpper(strings.TrimSpace(dtgTimeZoneLetter))
	if len(dtgTimeZoneLetter) > 1 || len(dtgTimeZoneLetter) < 1 || dtgTimeZoneLetter == `J` {
		return getLocalZone()
	}
	letter := rune(dtgTimeZoneLetter[0])
	if letter < 'A' || letter > 'Z' {
		return getLocalZone()
	}
	var hours rune = 0
	if letter == 'Z' {
		// Zulu time.
		hours = 0
	} else if letter >= 'A' && letter <= 'I' {
		// A to I are positive, A starts at +1.
		hours = 1 + (letter - 'A')
	} else if letter >= 'K' && letter <= 'M' {
		// K, L, M are also positive, K starts at +10.
	} else if letter >= 'N' && letter <= 'Y' {
		// N to Y are negative, N starts at -1.
		hours = -1 - (letter - 'N')
	}
	return time.FixedZone(fmt.Sprintf("%+03d00", int(hours)), int(hours)*3600)
}

func getLocalZone() *time.Location {
	t := time.Now()
	_, offset := t.Zone()
	return time.FixedZone(t.Format(numericTimeZoneLayout), offset)
}
