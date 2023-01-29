// Project Krypto431 is a simple OTP (One Time Pad) based on the DIANA
// cryptosystem utilizing a reciprocal table with single-use keys. Krypto431 is
// a CLI (command-line interface, cmd/krypto431) tool, an API (this package) and
// a traditional pen-and-paper cipher. The tool is provided for Linux,
// BSD-derivatives and Windows.
//
// # Purpose
//
// Krypto431 was designed to ease and facility passing sensitive information
// over any mode of communication, with or without electronic equipment.
// Although the system can be managed without a computer, the tool is an aid to
// generate, manage, and distribute keys to multiple stations and also simplify
// the message exchange (encoding, enciphering, deciphering, and decoding).
//
// Naturally, the intended particular purpose of this type of cipher is to
// encrypt messages in a contested (electronically and otherwise) hostile
// environment. Stations can be fully *within* enemy lines (civilian resistance
// movement) as well as *beyond* enemy lines (armed resistance, remote
// reconnaissance, etc). Another obvious purpose would be to encrypt sensitive
// information (such as casualties, names, addresses for example) during
// emergency communication.
//
// Although primarily not intended for amateur radio, we are allowed to exchange
// encrypted messages over ham radio within Sweden as long as our call-signs can
// be decoded. This allows us to practice sending and receiving old-style
// radiogram formatted crypto-group messages over telegraphy as well as voice,
// RTTY or a more modern data mode of choice.
//
// # Status
//
// v0.1.x is a proof-of-concept, lack unit tests and examples. See README.md for
// more information.
package krypto431
