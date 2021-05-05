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
example A=1) with the randomly generated number from the key. If the number is
26 or above, you wrap it starting from 0 (modulo 26). None of the numbers in
the key can be 0 and must only be numbers from 1 to 26.

When decrypting, you subtract the random number in the key from the ciphered
numerical representation of the letter. If the number is negative, you wrap it
around starting from 26 (or, for example 4 minus number from the key, e.g 18 =
`(26+4-18)%26 = 12 = L`).

If the encryptor has enciphered the whole message and is left with a final
group of less than 5 letters, the encryptor should add zeroes to the plaintext
(0, read more below) to fill up any remaining group (this is effectively
copying the number from the key to the ciphertext until the final group is
complete with 5 letters).

## Modulo 26

If you only have 26 letters and each letter represents a number from 1 to 26,
how do you send numbers? If the encryptor simply copies the key number to the
ciphertext (effectively adding it with zero, e.g 0+key=key), the result will be
0 when deciphered.

A single 0 indicates a space. The rule with Krypto431 is there can never be 2
spaces in a row since that has another purpose. Krypto431 uses modulo 26, but
`26 % 26 = 0`. When generating the key, the resulting number is incremented
by 1 so that the key can never contain the number 0.

With Krypto431, if the plaintext or deciphered number 0 appears twice, it
instructs the decryptor to change to an alternate character table (or change
back to the original A to Z character table) consisting of an additional 24
characters and 2 control symbols.

## Numbers and case sensitivity?

Not many traditional ciphers allow you to switch case from upper to lower. It
makes sense, there is no case in traditional modes like CW (Morse code) or
RTTY. However, in the digital age it would be convenient to be able to send
information such as passwords or encryption keys which is why Krypto431 is
designed to cover all necessary characters to send base64 encoded content (even
if the length of such a message is far from recommended). Complex passwords or
binary data must be sent base64 encoded, there are only 2 character tables with
a total of 50 characters - not even enough to cover the ASCII table.

The 25th position in the alternate character table is an instruction to change
the case from the default uppercase to lowercase (like pressing the CapsLock
key). This also changes back to the primary character table (A-Z). To change
back to uppercase you do the same thing: 0, 0, 25.

## Message spans the length of several keys?

The 26th position in the alternate character table instructs the decryptor that
the next 5 numbers (letters) is a key identifier. The new key is to be used to
decipher the letters/numbers that follow, just like a new Krypto431 ciphertext
would start except that the key id is encrypted and not written in plaintext
(only the first 5 letter group is plaintext and identifies the initial key for
encryption/decryption). This is useful if your message spans more than the
length of one key, you can simply repeat changing keys as necessary. Please
keep in mind that you need to change key before you run out of random numbers
in your current key (i.e there must be 6-8 numbers left when you decide to
change key depending on which character table you are currently in (primary or
alternate): 1-3 for the control character(s), 5 for the key identifier).
Immediately after the key everything is reset and you start on the primary
character table as per normal, but with the new key.

## Space

Space is simply 0, you copy the current random number in the key to the
ciphertext (effectively doing 0+key=key). When the decryptor deciphers the
position to 0 from the ciphertext, he or she enters a space in the deciphered
message.

## Primary character table

```
ABCDEFGHIJKLMNOPQRSTUVWXYZ
Q = Space
Z = Change to alternate character table
```

## Alternate character table

```
0123456789!+,-./=?Z@ ÅÄÖX[cl][change-to-key-that-follows]

0123456789ÅÄÖÆØ.Q?Z+/=,[cl][change-key][change-table]
ABCDEFGHIJKLMNOPQRSTUVWX   Y           Z
Z = Change to primary character table

When in the primary character table you decipher the following...
0, 0, 26
...it means that the next 5 characters indicate which key to change to. This
is useful if the message is longer than the length of a single key and makes it
possible to send a long message as a single message without needing to fragment
it into multiple message parts.

If you decipher 0, 0, 25 it's like pushing the CapsLock key, you indicate that
you want to switch the case from upper to lower and vice versa. It also means
to switch back to the primary character table (no need to add two zeroes as you
would do otherwise to switch back from the alternate to the primary character
table).
```

## Caveats - logic needed

```
ENCRYPTION

 plaintext: XYZ ABC = 24, 25, 26, 0, 1, 2, 3
       key: ZZZZZZZ = 26, 26, 26, 26, 26, 26, 26
       sum:           50, 51, 52, 26, 27, 28, 29
modulo26+1: YZAABCD = 25, 26, 1, 1, 2, 3, 4

DECRYPTION

ciphertext: YZAABCD = 25, 26, 1, 1, 2, 3, 4
       key: ZZZZZZZ = 26, 26, 26, 26, 26, 26, 26
  subtract:           -1, 0, -25, -25, -24, -23, -22
modulo26-1: XY  ABC
deciphered: XY  ABC


SOLUTION

ENCRYPTION

 plaintext: XYZ ABC = 24, 25, 26, 0, 1, 2, 3
       key: ZZZZZZZ = 26, 26, 26, 26, 26, 26, 26
       sum:           50, 51, 52, 26, 27, 28, 29
modulo26+1: YZAABCD = 25, 26, 1, 1, 2, 3, 4

ABC DEF
ABCZZDEF


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





zoo = ZZZOO
Zebra = ZZZEBRA

Marxzell = MARXXZELL (nope, see above)
Marxzell = MARXZXXZELL

This is a secret message. 123. 73
THISXISXAXSECRETXMESSAGEXZQXZXXZBCDQXZXXZHD











```



## Manually generating a key with dice

You need at least one square dice able to generate a number from 1 to 6,
preferably you would want 5 square dice. If you throw that dice 5 times (or all
5 dice once) and add all the numbers, the smallest number you can generate is
5. We want to generate numbers from 1 to 26. If we subtract 4 from the sum the
smallest number we can generate is now 1. The largest number we can generate is
`6*5 = 30`, but we still need to subtract 4 which means the largest number is
now 26. Perfect!

This is a simple way to generate a key if you - for some reason - can not use
electronics or the tools provided in this repository. Or, you have run out of
pre-generated pre-distributed keys and - since it's the apocalypse - you can
for some reason not access or use a computer. Well, if your trasceiver works
chances are that someone's laptop does aswell, but maybe you do not have the
electricity needed and since your transceiver is designed for 12 volts, it is
easy to connect to the generator in the nearest car. A QRP radio may also work
fine on AA batteries which your laptop definitely does not.

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

## Links



<https://youtu.be/cpqwp2H0SNo>

## 431

```
X=0 ; for i in $(echo -n SA6MWA | hexdump -e '1/1 "%d "'); do let X=$X+$i ; done ; echo $X
431

# or...

echo -n SA6MWA | sum -s
431 1
```

# Author

SA6MWA Michel <sa6mwa@radiohorisont.se>
