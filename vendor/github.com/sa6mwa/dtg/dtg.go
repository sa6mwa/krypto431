package dtg

// github.com/sa6mwa/dtg Copyright (C) 2022 SA6MWA Michel Blomgren.

// Format derived from Allied Communication Publication, ACP 121: COMMUNICATION
// INSTRUCTIONS GENERAL

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"
)

var (
	DtgRegexp                *regexp.Regexp = regexp.MustCompile(`^([0-9]{2})([0-9]{2})([0-9]{2})([A-Z]{0,1})(JAN|FEB|MAR|APR|MAY|JUN|JUL|AUG|SEP|OCT|NOV|DEC){0,1}([0-9]{2}){0,1}$`)
	ErrInvalidDTG            error          = errors.New("invalid DTG format (minimally ddHHMM to complete ddHHMMZmmmYY)")
	ErrInvalidTimeZoneLetter error          = errors.New("invalid time zone letter")
	ErrInvalidDtgVariadic    error          = errors.New("invalid DTG slice passed as variadic")
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
	numericTimeZoneLayout string = `-0700`
	expandedDtgLayout     string = `021504-0700Jan06`
	dayLayout             string = `02`
	hourLayout            string = `15`
	minuteLayout          string = `04`
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
		letter = 'N'
		letter -= rune(hours + 1)
	}
	return dtg.Time.Format(`021504`) + string(letter) + strings.ToUpper(dtg.Time.Format(`Jan06`))
}

// Parse transforms a NATO (ACP 121 Communication Instructions General) Date
// Time Group into a time.Time object via the DTG struct. The String() function
// of the DTG object reproduces a full Date Time Group from the time.Time object.
func Parse(dtgString string) (dtg DTG, err error) {
	dtgString = strings.ToUpper(strings.TrimSpace(dtgString))
	matches := DtgRegexp.FindAllStringSubmatch(dtgString, 1)
	if len(matches) != 1 || len(matches[0]) != 7 {
		return dtg, ErrInvalidDTG
	}
	match := matches[0]
	var numericTimeZone *time.Location
	numericTimeZone, err = GetNumericTimeZone(match[dtgSubMatchTimeZone], match[dtgSubMatchDay], match[dtgSubMatchHour], match[dtgSubMatchMinute], match[dtgSubMatchMonth], match[dtgSubMatchYear])
	if err != nil {
		return dtg, err
	}
	if utf8.RuneCountInString(match[dtgSubMatchMonth]) < 3 {
		match[dtgSubMatchMonth] = strings.ToUpper(time.Now().In(numericTimeZone).Format(monthLayout))
	}
	if utf8.RuneCountInString(match[dtgSubMatchYear]) < 2 {
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

// Return a time.Location (and error) with the numeric time zone representation
// (e.g +0100 or -1100) of an ACP 121 time zone letter (A-Z). Name field will be
// the numeric time zone (to parse with -0700). The variadic
// dayHourMinuteMonthYear string slice (optional) will parse this into a
// time.Time to use instead of time.Now() for the local time zone letter J (to
// present a daylight saving - DST - compensated offset). There is a String()
// function in time.Location to extract the numeric time zone as name is
// non-exported.
//
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
func GetNumericTimeZone(dtgTimeZoneLetter string, dayHourMinuteMonthYear ...string) (*time.Location, error) {
	dtgTimeZoneLetter = strings.ToUpper(strings.TrimSpace(dtgTimeZoneLetter))
	if utf8.RuneCountInString(dtgTimeZoneLetter) > 1 {
		return nil, ErrInvalidTimeZoneLetter
	} else if utf8.RuneCountInString(dtgTimeZoneLetter) < 1 {
		dtgTimeZoneLetter = "J"
	}
	letter := int([]rune(dtgTimeZoneLetter)[0])
	if letter < 'A' || letter > 'Z' {
		return nil, ErrInvalidTimeZoneLetter
	}
	if letter == 'J' {
		var localTime time.Time
		var err error
		layout := dayLayout + hourLayout + minuteLayout + monthLayout + yearLayout
		location := time.Now().Location()
		switch len(dayHourMinuteMonthYear) {
		case 0:
			localTime = time.Now()
		case 1:
			remaining := time.Now().Format(hourLayout + minuteLayout + monthLayout + yearLayout)
			localTime, err = time.ParseInLocation(layout, dayHourMinuteMonthYear[0]+remaining, location)
			if err != nil {
				// ddHHMM is mandatory
				return nil, err
			}
		case 2:
			remaining := time.Now().Format(minuteLayout + monthLayout + yearLayout)
			localTime, err = time.ParseInLocation(layout, strings.Join(dayHourMinuteMonthYear, "")+remaining, location)
			if err != nil {
				// ddHHMM is mandatory
				return nil, err
			}
		case 3:
			remaining := time.Now().Format(monthLayout + yearLayout)
			localTime, err = time.ParseInLocation(layout, strings.Join(dayHourMinuteMonthYear, "")+remaining, location)
			if err != nil {
				// ddHHMM is mandatory
				return nil, err
			}
		case 4:
			if utf8.RuneCountInString(dayHourMinuteMonthYear[3]) < 3 {
				remaining := time.Now().Format(monthLayout + yearLayout)
				localTime, err = time.ParseInLocation(layout, strings.Join(dayHourMinuteMonthYear[:3], "")+remaining, location)
				if err != nil {
					return nil, err
				}
			} else {
				remaining := time.Now().Format(yearLayout)
				localTime, err = time.ParseInLocation(layout, strings.Join(dayHourMinuteMonthYear, "")+remaining, location)
				if err != nil {
					return nil, err
				}
			}
		case 5:
			m := dayHourMinuteMonthYear[3]
			y := dayHourMinuteMonthYear[4]
			if utf8.RuneCountInString(m) < 3 {
				m = time.Now().Format(monthLayout)
			}
			if utf8.RuneCountInString(y) < 2 {
				y = time.Now().Format(yearLayout)
			}
			localTime, err = time.ParseInLocation(layout, strings.Join(dayHourMinuteMonthYear[:3], "")+m+y, location)
			if err != nil {
				return nil, err
			}
		default:
			return nil, ErrInvalidDtgVariadic
		}
		_, offset := localTime.Zone()
		return time.FixedZone(localTime.Format(numericTimeZoneLayout), offset), nil
	}
	var hours int = 0
	if letter == 'Z' {
		// Zulu time.
		hours = 0
	} else if letter >= 'A' && letter <= 'I' {
		// A to I are positive, A starts at +1.
		hours = 1 + (letter - 'A')
	} else if letter >= 'K' && letter <= 'M' {
		// K, L, M are also positive, K starts at +10.
		hours = 10 + (letter - 'K')
	} else if letter >= 'N' && letter <= 'Y' {
		// N to Y are negative, N starts at -1.
		hours = -1 - (letter - 'N')
	}
	/* // Will never reach this...
	 	 else {
			return nil, ErrInvalidTimeZoneLetter
		}
	*/
	return time.FixedZone(fmt.Sprintf("%+03d00", hours), hours*3600), nil
}

// Validate attempts to parse the DTG string, discards the DTG object and
// returns error if parsing failed (invalid DTG) or nil (valid DTG).
func Validate(dtgString string) error {
	_, err := Parse(dtgString)
	return err
}
