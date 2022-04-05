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
# by Dwayne C. Litzenberger <dlitz@dlitz.net>.  It implements a
# file-like model in which a caller can request key bytes generated
# from a given password and salt in successive calls, as if reading
# from a stream.
#
# Copyright (C) 2022 Sigfredo Ismael Nin Colón (signin@email.com)
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
if (!require(R6)) install.packages('R6', quiet = TRUE)
suppressMessages(library (R6))         # R6 Classes

###########################################################################
# PBKDF2_READER Class
###########################################################################
PBKDF2_READER <- R6Class("PBKDF2_READER",

    private = list(
 
        # parameters

        passphrase = NULL,  # string to expand, as raw bytes
        salt = NULL,        # salt, as raw bytes
        iterations = NULL,  # number of times to recursively invoke hash on each block
        prf = NULL,         # pseudorandom function

        # state

        index = NULL,       # index of block to be next returned from inner function
        bytes = NULL,       # key bytes accumulated by calls to inner function
        closed = NULL,      # if FALSE, bytes can still be read from expanded key

        # private methods

        ###########################################################################
        # Convert a UTF-8 string to raw bytes.
        #
        # Inputs:
        #   obj     : the UTF-8 string to be converted
        ###########################################################################
        makeStringRaw = function(obj) {
            result = obj;
            if (!is.raw(obj)) {
                if (is.character(obj)) {
                    if (!validUTF8(obj)) stop("Input to makeStringRaw() must be a valid UTF-8 string or raw bytes.")
                    result <- charToRaw(obj)
                }
            }
            return(result)
        },

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
        uintToRaw = function(num, minLen=4) {
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
        },

        ###########################################################################
        # The internal function f in the PBKDF2 algorithm.  Returns a block of hlen
        # key bytes, where hlen is the block size of the underlying pseudorandom
        # function, prf().  The pseudorandom function takes a passphrase, a
        # variable-length raw vector; and a salt, also a variable-length raw vector;
        # it returns a (typically fixed length) raw vector.
        ###########################################################################
        f = function() {
            if (!(0 <= private$index && private$index <= ((2^32)-1)))
                stop ("Derived key too long.")
            U <- prf(private$passphrase, c(private$salt, uintToRaw(private$index)))
            result <- U
            if (private$iterations > 1) {
                for (j in 2:private$iterations) {
                    U <- private$prf(private$passphrase, U)
                    result <- xor(result, U)
                }
            }
            return(result)
        },

        ###########################################################################
        # HMAC using the SHA-256 hash algorithm.
        #
        # Inputs
        #   key     : secret key
        #   object  : data to compute the hash over
        ###########################################################################
        HMAC_SHA_256 = function(key, object) {
            hmac(key, object, algo="sha256", raw=TRUE)
        }

    ), # private list

    public = list(

        # initialization method

        ###########################################################################
        # Initialize the object instance.
        #
        # Inputs:
        #   passphrase  : String to be expanded into a key.
        #   salt        : Raw bytes to expand the set of possible keys.
        # Options:
        #   iterations  : Number of times to apply the pseudorandom function
        #                 when computing a key block in the function f
        #                 [default: 1000]
        #   prf:        : Pseudorandom function
        #                 [default: digest$hmac(algo="sha256")]
        ###########################################################################
        initialize = function(passphrase, salt, iterations=1000,
                              prf=private$HMAC_SHA_256) {

            # validate arguments
            if (!is.numeric(iterations)) stop("The iterations count must be a number.")
            if (iterations < 1) stop("The iterations count must be at least 1.")
            if (iterations > 2^32-1) stop("The iterations count cannot exceed 2^32-1 (0xFFFFFFFF).")
            if (!is.function(prf)) stop("The pseudorandom function prf must be a callable function.")

            # initialize parameters
            private$passphrase <- makeStringRaw(passphrase)
            private$salt <- makeStringRaw(salt)
            private$iterations <- iterations
            private$prf <- prf

            # initialize state
            private$index <- 1          # First block will be index 1
            private$bytes <- raw()      # There are no bytes yet
            private$closed <- FALSE     # The key bytes stream is available
        },
 
        # public methods

        ###########################################################################
        # Get the requested number of bytes from the expanded key.  Update the
        # the state of the expansion, so subsequent calls can continue where
        # this one left off.
        #
        # Inputs:
        #   dkLen       : Number of key bytes to return
        ###########################################################################
        read = function(dkLen) {
            if (private$closed) stop("The expanded key stream is closed, no more bytes can be read.")
            if (!is.numeric(dkLen)) stop("dkLen must be a number.")
            if (dkLen < 1) stop("dkLen must be at least 1.")
            while (length(private$bytes) < dkLen) {
                block <- private$f()
                private$bytes <- c(private$bytes, block)
                private$index <- private$index + 1
            }
            if (!(dkLen <= length(private$bytes)))
                stop("ERROR: stopped generating but bytes generated < dklen.")
            result <- private$bytes[1:dkLen]        # Requested key bytes
            bytesLeft = length(private$bytes) - dkLen
            if (bytesLeft > 0)
                private$bytes <- private$bytes[dkLen+1:length(private$bytes)]  # Leave remaining bytes
            else
                private$bytes <- raw()
            return(result)
        },

        close = function() {
            private$closed <- TRUE   # Make the stream of expanded key bytes inaccessible
        }

    ) # public list
) # R6Class
