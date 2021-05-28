# Krypto431

This is a simple OTP (One Time Pad) crypto system called Krypto431. 431 is the
sum of all ascii characters in my amateur radio callsign SA6MWA. As the name
suggests, the concept is to add or subtract in order to encrypt or decrypt a
text message. The system is designed to be easy to use without any electronic
equipment, just pen and paper.

## Why?

One may think One-Time-Pad (OTP) ciphers are pretty simple and straight
forward, but in order to be able to communicate, encrypt and decrypt messages
you need to agree on a format, consider key distribution and provide clear
instructions how to use such a system. If there ever is a need to pass
sensitive information in a short message format over an unsecure channel (for
example over radio telegraphy or radio telephony), there are no open civilian
solutions readily available (that I know of). Krypto431 was realized to provide
a standard and a set of tools for effectively passing encrypted messages that
can - if necessary - be deciphered (and enciphered) without an electronic or a
mechanical device.

## How

Traditionally, ciphertext has consisted of groups of 5 letters where the first
group identifies the key. When sending such a ciphertext (in for example
military radio communication) you indicate group count - how many groups of 5
letters there are to be sent/received. Krypto431 employs the same concept. The
first group consists of 5 letters that identify which key was used to encrypt
it and - since it's symmetric - which key to use for decrypting the ciphertext.
The remaining ciphertext is organized into groups of 5 letters.

When encrypting, you add the numerical representation of the letter (for
example A=0) with the randomly generated number from the key. If the number is
26 or above, you wrap it starting from 0 (modulo 26).

When decrypting, you subtract the random number in the key from the ciphered
numerical representation of the letter. If the number is negative, you wrap it
around starting from 26 (or, for example 4 minus number from the key, e.g 18 =
`(26+4-18)%26 = 12 = L`).

If the encryptor has enciphered the whole message and is left with a final
group of less than 5 letters, the encryptor should add Z to the plaintext to
fill up any remaining group as Z will be used as an operator character that
changes the character table to and from an alternate table. Filling up with Z
just changes the table back and forth without adding any real characters to the
output.

## Primary character table

```
ABCDEFGHIJKLMNOPQRSTUVWXYZ
Q = Space
Z = Change to alternate character table
```

## Alternate character table

```
0123456789ÅÄÖÆØ.Q?Z+/=,[cl][change-key][change-table]
ABCDEFGHIJKLMNOPQRSTUVWX   Y           Z
Z = Change to primary character table

```

```
NEW IDEA = TRUE MODULO 26, 0 to 25

rule = Z is only to switch between tables, can not be used in either table.

Z = change table
ZS = Z (Z is position S in the 2nd character table)
ZRZ = change table, R = space (room), change back to A-Z table
Padding to fill out 5 letter group = Z (change front to back between character tables)

Zoo = ZSZOO
Marxzell = MARXZSZELL
Zebra = ZSZEBRA

Z123 HELLO = ZSBCDRZHELLO = Z123 HELLO

This is a secret text. How are you doing? Take care, bye.
With ZRZ as "room" character:
THISZ RZISZ RZAZR ZSECR ETZRZ TEXTZ PRZHO WZRZA REZRZ YOUZR ZDOIN GZQRZ TAKEZ RZCAR EZWZB YEZPZ
With Q as space/room:
THISQ ISQAQ SECRE TQTEX TZPZQ HOWQA REQYO UQDOI NGZQZ QTAKE QCARE ZWZQB YEZPZ
Queens, cobras and zebras.
ZQZUE ENSZW ZQCOB RASQA NDQZS ZEBRA SZPZZ

UPK31 = UPKZD BZZZZ

UTGÅ MOT UPK79 = UTGZK ZQMOT QUPKZ HJZZZ

```

## Manually generating a key with dice

The previous method described here had the flaw of bias towards some numbers
while others do not appear as frequent resulting in a poor quality key -
thankfully pointed out by SA4AMX.

One possible solution was found
[here](https://medium.com/swlh/simulating-a-seven-sided-die-with-a-six-sided-one-28f73afc1702),
but it needs to be described dumb-simple for numbers 0 to 25.
[Here](https://medium.com/swlh/roll-your-own-random-number-generator-176bcd860363)
Thomas Langkaas explains some more.

```
tldr; Use 2 cube dices (6-sided). First roll selects range of second throw.
1  1  1  1  1  1  2  2  2  2  2  2  3  3  3  3  3  3  4  4  4  4  4  4  5  5
1  2  3  4  5  6  1  2  3  4  5  6  1  2  3  4  5  6  1  2  3  4  5  6  1  2
00 01 02 03 04 05 06 07 08 09 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25

If first roll of the dice is a 3 and second roll is a 4, the random number is
15. If the first throw is a 6 you simply discard it and roll the dice again.
Same thing if the first roll is a 5 and the second roll is 3, 4, 5 or 6 - you
re-roll until you get either 1 or 2. If the first roll is 5 and the second
is 1 the number is 24. If the first roll is 5 and the second is 2 the number is
25.
```

## Randomness

Krypto431 will use `crypto/rand` in the Golang implementation which in turn
prefer `getrandom(2)` on Linux systems or `/dev/urandom` as a fallback. We can
safely use `/dev/urandom` as it uses the exact same CSPRNG (Cryptographically
Secure Pseudo Random Number Generator) as `/dev/random`. Entropy is not an
issue if you have enough to start with (256 bits) and this program will not run
at boot at the exact same time as a virtual machine that uses the exact same
seed on every boot. So the issue with using `/dev/urandom` does not exist. By
using `crypto/rand` on a Linux system above 3.17 (or something) we use
`getrandom(2)` which will block until enough initial entropy has been gathered
and will never block again - exactly what we want.

Reference: <https://www.2uo.de/myths-about-urandom/>

## Encrypted sqlite3

There are a few options in Go...

* <https://github.com/mutecomm/go-sqlcipher>
* <https://github.com/CovenantSQL/go-sqlite3-encrypt>
* <https://github.com/xeodou/go-sqlcipher>

## Secure key generation

Links to things related to cryptographically secure PRNG/RNG and 

* Implement Lemire's debiased integer multiplication method? <https://www.pcg-random.org/posts/bounded-rands.html>
* LICENSE ISSUE (GPL-3.0): Pure Go implementation of Mersenne Twister PRNG <https://pkg.go.dev/github.com/seehuhn/mt19937>
* MIT License MT19937 version: <https://github.com/spiegel-im-spiegel/mt> 

The Go `math/rand` PRNG is said to be from Plan9's rand(2) implementation and
is an **Additive Lagged Fibonacci Generator (ALFG)** which is not considered
secure by todays standards.
<https://en.wikipedia.org/wiki/Lagged_Fibonacci_generator>.

```
It's an Additive Lagged Fibonacci Generator (ALFG)
described by S_n ≡ S_(n-273) + S_(n-607) mod 2^31.
It's the same code used in Plan 9's rand(2).
```
[Source](https://grokbase.com/t/gg/golang-nuts/137fejwsem/go-nuts-math-rand-package-underlying-algorithm#20130715lfzbivfzx6567dx7vz3babsvvu)

Using [Stefan Nilsson's approach](https://yourbasic.org/golang/crypto-rand-int/) by initiating a new source (not NewSource, but New(source)) makes it possible to use `math/rand` with an external pseudo random number generator (for example `crypto/rand` which is cryptographically secure).

```go
// A Source represents a source of uniformly-distributed
// pseudo-random int64 values in the range [0, 1<<63).
type Source interface {
	Int63() int64
	Seed(seed int64)
}

// A Source64 is a Source that can also generate
// uniformly-distributed pseudo-random uint64 values in
// the range [0, 1<<64) directly.
// If a Rand r's underlying Source s implements Source64,
// then r.Uint64 returns the result of one call to s.Uint64
// instead of making two calls to s.Int63.
type Source64 interface {
	Source
	Uint64() uint64
}

/* ... */

// New returns a new Rand that uses random values from src
// to generate other random values.
func New(src Source) *Rand {
	s64, _ := src.(Source64)
	return &Rand{src: src, s64: s64}
}
```

So we need at least `Int63()` and `Seed()`. Usually we can get a Uint64 and
mask off a bit to get the `Int63()`, which is what Stefan
Nilsson's implementation does.

The `Seed()` function can be completely empty in this case as it's already
seeded by the operating system through `crypto/rand`.

## Other links

<https://youtu.be/cpqwp2H0SNo>

## 431

```
X=0 ; for i in $(echo -n SA6MWA | hexdump -e '1/1 "%d "'); do let X=$X+$i ; done ; echo $X
431

# or...

echo -n SA6MWA | sum -s
431 1
```

# Authors

See the  `AUTHORS` file.
