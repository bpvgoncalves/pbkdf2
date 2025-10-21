
# PBKDF2-HMAC-SHA1 -----------------------------------------------------------------------
#' HMAC_SHA1
#'
#' @param key     HMAC key
#' @param object  object ro be hashed
#'
#' @keywords internal
#'
HMAC_SHA_1 <- function(key, object) {
  digest::hmac(key, object, algo="sha1", raw=TRUE)
}

# PBKDF2-HMAC-SHA2 -----------------------------------------------------------------------
#' HMAC-SHA2
#'
#' @param key     HMAC key
#' @param object  object ro be hashed
#'
#' @keywords internal
#'
HMAC_SHA_256 <- function(key, object) {
  digest::hmac(key, object, algo="sha256", raw=TRUE)
}
