###########################################################################
# pbkdf2 - PKCS #5: Password-Based Cryptography Version 2.1
#
# IETF RFC 8018 January 2017
#   This implementation uses a pseudorandom function (PRF) based
#   on an HMAC (e.g., FIPS-NIST-198) and a hash function (e.g., SHA-1,
#   SHA-2, FIPS-NIST-180); by default, HMAC-SHA-256.
#
# PBKDF2 takes a passphrase and a salt and returns a requested
# number, dkLen, of key bytes.  It generates the key bytes by repeatedly
# calling an internal function, f, until it has concatenated together
# enough blocks to return the requested number of key bytes. 
# The function f recursively calls a pseudorandom function a requested
# number of iterations to produce a block of bytes to add to the key.
# The pseudorandom function is usually (and by default) an HMAC based on a
# hash function, such as specified in FIPS-NIST-198.
# The PBKDF2 algorithm is described in detail in ITEF RCF 8018. 
# 
# This implementation is inspired by the 2007-2011 Python program
# by Dwayne C. Litzenberger <dlitz@dlitz.net>.  However, it does not
# use the file-like model, but instead implements the straightforward
# model from RCF 8018 in which a single call to PBKDF2 generates and
# returns all of the requested dkLen key bytes.
#
# Copyright (C) 2022 Sigfredo I. Nin (signin@email.com)
#
# Permission is hereby granted, free of charge, to any person obtaining
# a copy of this software and associated documentation files (the
# "Software"), to deal in the Software without restriction, including
# without limitation the rights to use, copy, modify, merge, publish,
# distribute, sublicense, and/or sell copies of the Software, and to
# permit persons to whom the Software is furnished to do so, subject to
# the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
# LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
# OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
# WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
#
# Country of origin: USA
#
###########################################################################

if (!require(digest)) install.packages('digest', quiet = TRUE)
suppressMessages(library (digest))     # HMAC and SHA-256 for pseudorandom function

###########################################################################
# Convert a UTF-8 string to raw bytes.
#
# Inputs:
#   obj     : the UTF-8 string to be converted
###########################################################################
makeStringRaw <- function(obj) {
    result = obj;
    if (!is.raw(obj)) {
        if (is.character(obj)) {
            if (!validUTF8(obj)) stop("Input to makeStringRaw() must be a valid UTF-8 string or raw bytes.")
            result <- charToRaw(obj)
        }
    }
    return(result)
}

###########################################################################
# Convert an unsigned integer from R numeric to its big-endian binary form.
# Used to convert the index argument of the f function into the required
# 4-byte vector to append to the salt.
#
# Inputs:
#   num     : the number, which must be positive with no fractional part
# Options:
#   minLen  : the minimum number of bytes in the result
#             [default: 4]
###########################################################################
uintToRaw <- function(num, minLen=4) {
    if(0 > num) stop(paste(num, "is not positive."))
    if(0 != num %% 1) stop(paste(num, "is not an integer."))
    raw <- raw()
    rem <- num
    repeat {
        lo <- rem %% 256
        rem <- rem %/% 256
        raw <- c(as.raw(lo), raw)
        if (rem == 0 && minLen <= length(raw)) break
    }
    return(raw)
}

###########################################################################
# The internal function f in the PBKDF2 algorithm.  Returns a block of hlen
# key bytes, where hlen is the block size of the underlying pseudorandom
# function, prf().  The pseudorandom function takes a passphrase, a
# variable-length raw vector; and a salt, also a variable-length raw vector;
# it returns a (typically fixed length) raw vector.
#
# Inputs:
#   passphrase  : String to be expanded into a key.
#   salt        : Raw bytes to expand the set of possible keys.
#   iterations  : Number of times to apply the pseudorandom function
#   prf:        : Pseudorandom function ()
#   index       : the block index to append to the salt in the first prf call
###########################################################################
f_PBKDF2 <- function(passphrase, salt, iterations, prf, index) {
    if (!is.numeric(index)) stop("The index must be a number.")
    if (!(0 <= index && index <= ((2^32)-1)))
        stop ("Derived key too long.")
    U <- prf(passphrase, c(salt, uintToRaw(index)))
    result <- U
    if (iterations > 1) {
        for (j in 2:iterations) {
            U <- prf(passphrase, U)
            result <- xor(result, U)
        }
    }
    return(result)
}

###########################################################################
# Get the requested number of bytes from the expanded key.
#
# Inputs:
#   passphrase  : String to be expanded into a key.
#   salt        : Raw bytes to expand the set of possible keys.
#   dkLen       : Number of key bytes to return
# Options:
#   iterations  : Number of times to apply the pseudorandom function
#                 when computing a key block in the function f
#                 [default: 1000]
#   prf:        : Pseudorandom function
#                 [default: digest$hmac(algo="sha256")]
###########################################################################
HMAC_SHA_256 <- function(key, object) {
    hmac(key, object, algo="sha256", raw=TRUE)
}
PBKDF2 <- function(passphrase, salt, dkLen, iterations=1000,
                      prf=HMAC_SHA_256) {
    passphrase <- makeStringRaw(passphrase)
    salt <- makeStringRaw(salt)
    if (!is.numeric(dkLen)) stop("The dkLen must be a number.")
    if (dkLen < 1) stop("The dkLen must be at least 1.")
    if (!is.numeric(iterations)) stop("The iterations count must be a number.")
    if (iterations < 1) stop("The iterations count must be at least 1.")
    if (iterations > 2^32-1) stop("The iterations count cannot exceed 2^32-1 (0xFFFFFFFF).")
    if (!is.function(prf)) stop("The pseudorandom function prf must be a callable function.")
    bytes <- raw()
    index <- 1
    while (length(bytes) < dkLen) {
        block <- f_PBKDF2(passphrase, salt, iterations, prf, index)
        bytes <- c(bytes, block)
        index <- index + 1
    }
    return(bytes[1:dkLen])
}
