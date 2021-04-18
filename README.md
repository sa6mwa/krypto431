# Krypto431

This is a simple OTP (One Time Pad) crypto system called Krypto431. 431 is the
System V sum algorithm checksum of my amateur radio callsign SA6MWA.

```
echo -n SA6MWA | sum -s
431 1
```

OTP is simple, but in order to be able to communicate, encrypt and decrypt
messages you need to format the cipher text. Traditionally this has been in
groups of 5 numbers or letters. Krypto431 uses 5 letter groups where the first
group sent or received identifies which cryptographic key can be used to
decipher the text (and which key was used to encipher the text). This is a
symmetric encryption, meaning you use the same key to encrypt and decrypt the
message.

This repo contains a set of tools written in Golang to produce keys you can
distribute and instructions how to manually encrypt and decrypt text in the
Krypto431 format.
