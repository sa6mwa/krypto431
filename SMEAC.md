
O: 001
S: We need to persist keys, texts, which keys have already been used, etc. We need to persist Krypto431 structs.
M: Persist Krypto431 struct by storing data as a compacted json encrypted gzip file
E: Marshall json as a compact struct, gzip and encrypt those bytes with some form of aes256. Put salt in the beginning from crand and read key from terminal (MVP) and file (MVP2).

O: 002 
S: We are missing the encipher function (encode and encipher)
M: Write function to encipher PlainText into CipherText
E: Continue where we left off.

O: 003
S: The decipher function is missing (decipher and decode)
M: Write function to decipher CipherText into PlainText
E: Finish 002 first, then refine this COA.

