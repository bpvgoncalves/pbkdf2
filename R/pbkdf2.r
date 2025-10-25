###########################################################################
# pbkdf2 - PKCS #5: Password-Based Cryptography Version 2.1
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

#' f function
#'
#' The internal function f in the PBKDF2 algorithm.  Returns a block of hlen
#' key bytes, where hlen is the block size of the underlying pseudorandom
#' function, prf().  The pseudorandom function takes a passphrase, a
#' variable-length raw vector; and a salt, also a variable-length raw vector.
#'
#' @param passphrase String to be expanded into a key.
#' @param salt       Raw bytes to expand the set of possible keys.
#' @param iterations Number of times to apply the pseudorandom function
#' @param prf        Pseudorandom function()
#' @param index      the block index to append to the salt in the first prf call
#'
#' @returns  It returns a (typically fixed length) raw vector.
#' @keywords internal
#'
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

#' PBKDF2
#'
#' Get the requested number of bytes from the expanded key.
#'
#' @details
#' PBKDF2 takes a passphrase and a salt and returns a requested number -
#' dkLen - of key bytes.   It generates the key bytes by repeatedly
#' calling an internal function, f, until it has concatenated together
#' enough blocks to return the requested number of key bytes.
#' The function f recursively calls a pseudorandom function a requested
#' number of iterations to produce a block of bytes to add to the key.
#' The pseudorandom function is usually (and by default) an HMAC based
#' on a hash function, such as specified in FIPS-NIST-198.
#' The PBKDF2 algorithm is described in detail in IETF RFC 8018.
#'
#' This implementation is inspired by the 2007-2011 Python program
#' by Dwayne C. Litzenberger <dlitz@dlitz.net>.  However, it does not
#' use the file-like model, but instead implements the straightforward
#' model from RFC 8018 in which a single call to PBKDF2 generates and
#' returns all of the requested dkLen key bytes.
#'
#' @references
#' - IETF RFC 8018 January 2017
#' - NIST FIPS-198
#'
#' @param passphrase  String to be expanded into a key.
#' @param salt        Raw bytes to expand the set of possible keys.
#' @param dkLen       Number of key bytes to return.
#' @param iterations  Number of times to apply the pseudorandom function when
#'                    computing a key block in the function f (default = 1000)
#' @param prf         Pseudorandom function (default = HMAC_SHA2_256)
#'
#' @returns  An object of type `pbkdf2_key`, including a key with the requested
#' length and metadata about the key generation.
#'
#' @export
#'
#' @examples
#' key <- PBKDF2("pass", "salt", 32)
#' key
#'
PBKDF2 <- function(passphrase, salt, dkLen, iterations=1000, prf=HMAC_SHA2_256) {
    passphrase <- makeStringRaw(passphrase)
    salt <- makeStringRaw(salt)
    if (!is.numeric(dkLen)) stop("The dkLen must be a number.")
    if (dkLen %% 1 != 0) stop("The dkLen must be an integer.")
    if (dkLen < 1) stop("The dkLen must be at least 1.")
    if (!is.numeric(iterations)) stop("The iterations count must be a number.")
    if (iterations %% 1 != 0) stop("The iterations count must be an integer.")
    if (iterations < 1) stop("The iterations count must be at least 1.")
    if (iterations > 2^32-1) stop("The iterations count cannot exceed 2^32-1 (0xFFFFFFFF).")
    if (is.null(prf)) stop("The pseudorandom function prf must be a callable PRF function or OID.")
    if (!is.function(prf)) {
        if (is.character(prf) & prf %in% algorithm_list$oid) {
            algo <- prf
            prf <- get(oid_to_name(prf))
        } else if (is.character(prf) & prf %in% algorithm_list$frdly_name) {
            algo <- name_to_oid(prf)
            prf <- get(prf)
        } else {
            stop("The pseudorandom function prf must be a callable PRF function or OID.")
        }
    } else {
        if (!(deparse(substitute(prf)) %in% algorithm_list$frdly_name)) {
            stop("The pseudorandom function prf must be a known PRF function or OID.")
        }
        algo <- name_to_oid(deparse(substitute(prf)))
    }
    bytes <- raw()
    index <- 1
    while (length(bytes) < dkLen) {
        block <- f_PBKDF2(passphrase, salt, iterations, prf, index)
        bytes <- c(bytes, block)
        index <- index + 1
    }

    params <- list(salt = salt,
                   len = dkLen,
                   iter = iterations,
                   prf = algo)
    params <- structure(params, class = c("pbkdf2_parameters", class(params)))

    structure(list(masterkey = bytes[1:dkLen], parameters = params), class = "pbkdf2_key")
}
