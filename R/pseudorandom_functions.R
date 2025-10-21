
# PBKDF2-HMAC-SHA1 -----------------------------------------------------------------------
#' HMAC-SHA1
#'
#' Pseudorandom function to apply HMAC with SHA1 hash algorithm
#'
#' @param key     HMAC key
#' @param object  object ro be hashed
#' @export
HMAC_SHA1 <- function(key, object) {
  openssl::sha1(object, key)
}

# PBKDF2-HMAC-SHA2 -----------------------------------------------------------------------
#' HMAC-SHA2
#'
#' Pseudorandom functions to apply HMAC with SHA2 hash algorithms
#'
#' @param key     HMAC key
#' @param object  object ro be hashed
#' @export
#' @name HMAC_SHA2
HMAC_SHA2_224 <- function(key, object) {
  openssl::sha2(object, 224, key)
}

#' @rdname HMAC_SHA2
#' @export
HMAC_SHA2_256 <- function(key, object) {
  openssl::sha2(object, 256, key)
}

#' @rdname HMAC_SHA2
#' @export
HMAC_SHA2_384 <- function(key, object) {
  openssl::sha2(object, 384, key)
}

#' @rdname HMAC_SHA2
#' @export
HMAC_SHA2_512 <- function(key, object) {
  openssl::sha2(object, 512, key)
}
