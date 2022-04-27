# pbkdf2

PBKDF2 takes a passphrase and a salt and returns a requested number, dkLen, of key bytes.  It generates the key bytes by repeatedly calling an internal function, f, until it has concatenated together enough blocks to return the requested number of key bytes. The function f recursively calls a pseudorandom function a requested number of iterations to produce a block of bytes to add to the key. The pseudorandom function is usually (and by default) an HMAC based on a hash function, such as specified in FIPS-NIST-198.

The PBKDF2 algorithm is described in detail in IETF RFC 8018.

## R/Basic

This is the R programming 101 version.  A call to the PBKDF2 function computes and returns the requested number of key bytes.  This is an advantage if only a small number of key bytes are required, as in the usual case of generating one key to encrypt some data.  It may be a disadvantage if a large number of key bytes are needed, as when a set of keys are to be generated from the same password.

## R/R6

This the R6 OOP version. The PBDKF2_READER class is instantiated with the password, salt, number of iterations, and HMAC function to be used in the algorithm.  The read(count) method generates enough blocks to return the requested number of expanded key bytes.  If the count is not a multiple of the underlying block size (the hash length), then read(count) saves the leftover bytes.  Additional calls to read(count) return subsequent bytes from the sequence defined by the parameters, beginning with any leftover bytes, as if reading from a stream.  The close() method makes the remainder of the expanded key bytes inaccesible, so further calls to read(count) will throw an error.  The close() method also resets the internal variables to remove references to the parameters and any leftover state.

## Unit Tests

In PBKDF2, the actual calculations that map a passphrase and salt to key bytes are carried out in the pseudorandom function, either one specified as an argument, or the default hmac with algorithm sha-256 in the r digest package.  The unit tests verify that the pseudorandom function is called correctly and that the resulting key bytes are assembled and selected correctly to provide the result. The unit tests rely primarily on published test vectors, but can also rely on the results of direct calls to the specified pseudorandom function for some simple cases, such as when the test specifies just one iteration.

The unit tests check usage with MD5, SHA-1, SHA-224, SHA-384, SHA-256, and SHA-512.  SHA-256 is tested using the default pseudorandom function. All are tested with iterations as large as 10,000, and SHA-256 also at 80,000.  Some tests are built into the unit test source, but many (from Anti-weakpasswords) are specified in .csv files, which makes it easy to add tests to meet unique requirements.

## References

IETF RFC 8018  
    PKCS #5: Password-Based Cryptography Specification Version 2.1  
    January 2017  
    Definition of function PBKDF2

IETF RFC 7914  
    The scrypt Password-Based Key Derivation Function  
    August 2016  
    Includes test vectors for PBKDF2 with HMAC-SHA-256.

IETF RFC 6070  
    PKCS #5: Password-Based Key Derivation Function (PBKDF2) Test Vectors  
    January 2011  
    PBKDF2-HMAC-SHA1 test vectors

IETF RFC 4231  
    Identifiers and Test Vectors for HMAC-SHA-224, HMAC-SHA-256, HMAC-SHA-384, and HMAC-SHA-512  
    December 2005  
    Test vectors for SHA2 HMAC variants that can be used as the pseudorandom function in PBKDF2.

IETF RFC 2104  
    HMAC: Keyed-Hashing for Message Authentication  
    February 1997  
    Specifies HMAC using a generic cryptographic function.

PBKDF2 Test Vectors  
     https://github.com/Anti-weakpasswords/PBKDF2-Test-Vectors/releases  
     March 2014  
     Test vectors for PBKDF2 with HMAC -MD-5, -SHA-1, -SHA-224, -SHA-256,  
     -SHA-384, -SHA-512 validated on over a half dozen PBKDF2 implementations.  
     See the author's post at:  
     https://stackoverflow.com/questions/5130513/pbkdf2-hmac-sha2-test-vectors

PBKDF2 HMAC-SHA-2 Test Vectors  
    https://github.com/brycx/Test-Vector-Generation/blob/master/PBKDF2/pbkdf2-hmac-sha2-test-vectors.md  
    January 2019

FIPS-NIST-180-4  
    Secure Hash Standard,  
    http://dx.doi.org/10.6028/NIST.FIPS.180-4  
    August 2015  
    Specifies SHA-1, SHA-224, SHA-256, SHA-384, SHA-512, SHA-512/224 and SHA-512/256.

FIPS-NIST-198  
    The Keyed-Hash Message Authentication Code (HMAC)  
    July 2008  
    Describes a keyed-hash message authentication code (HMAC), that can be used with any  
    iterative Approved cryptographic hash function, in combination with a shared secret key.

## License (MIT License)

Copyright © 2022 Sigfredo Ismael Nin Colón (signin@email.com)

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

Country of Origin: USA
