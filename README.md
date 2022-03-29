# pbkdf2

Implementations of the PBKDF2 function defined in IETF RCF 8018.

PBKDF2 takes a passphrase and a salt and returns a requested number, dkLen, of key bytes.  It generates the key bytes by repeatedly calling an internal function, f, until it has concatenated together enough blocks to return the requested number of key bytes. The function f recursively calls a pseudorandom function a requested number of iterations to produce a block of bytes to add to the key. The pseudorandom function is usually (and by default) an HMAC based on a hash function, such as specified in FIPS-NIST-198.

The PBKDF2 algorithm is described in detail in ITEF RCF 8018.

## R/Basic

This is the R programming 101 version.  A call to the PBKDF2 function computes and returns the requested number of key bytes.  This is an advantage if only a small number of key bytes are required, as in the usual case of generating one key to encrypt some data.  It may be a disadvantage if a large number of key bytes are needed, as when a set of keys are to be generated from the same password.

## License (MIT License)

Copyright © 2022 Sigfredo Ismael Nin Colón (signin@email.com)

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

Country of Origin: USA
