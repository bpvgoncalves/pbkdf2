
#' HKDF - Extract
#'
#' Internal invariant:
#'   - `salt` and `ikm` are raw vectors
#'   - `hash` is a function(key, data) -> raw
#'   - Validation is guaranteed by the public wrapper
#'
#' @param salt raw vector
#' @param ikm  raw vector
#' @param hash hmac-hash function
#'
#' @returns raw vector
#'
#' @keywords internal
hkdf_extract <- function(salt, ikm, hash) {

  # RFC 5869 §2.2
  # PRK = HMAC-Hash(salt, IKM)
  hash(salt, ikm)
}


#' HKDF - Expand
#'
#' Internal invariant:
#'   - `prk`, `info` are raw vectors
#'   - `len` is a positive integer <= 255*HashLen
#'   - `hash` is a function(key, data) -> raw
#'
#' @param prk  raw vector
#' @param info raw vector
#' @param len  positive integer
#' @param hash hmac-hash function
#'
#' @returns raw vector
#'
#' @keywords internal
hkdf_expand <- function(prk, info, len, hash) {

  t <- raw(0)
  out <- raw(len)
  pos <- 1L
  i <- 0L

  while (pos <= len) {
    i <- i + 1L
    if (i > 255L)
      stop("Internal counter exceeded 255 blocks.")

    t <- hash(prk, c(t, info, as.raw(i)))

    need <- min(length(t), len - pos + 1L)
    out[pos:(pos + need - 1L)] <- t[seq_len(need)]
    pos <- pos + need
  }

  out
}



#' HKDF - HMAC-based Extract-and-Expand Key Derivation Function (RFC-5869)
#'
#' Derive a key using the HMAC-based Extract-and-Expand Key Derivation Function (HKDF).
#' This function performs `Extract` (HMAC(salt, IKM)) followed by `Expand` to produce
#' `len` bytes of output key material (OKM).
#'
#' @param salt (character or raw) Optional salt value. If `NULL` or empty, a string of zeros
#'   equal to the PRF's hash output length is used (per RFC 5869).
#' @param ikm (character or raw) Input keying material. Must be provided.
#' @param info (character or raw) Optional context/application-specific info string.
#' @param len (integer) Length in bytes of output keying material. Must be positive and
#'   not greater than `255 * HashLen`, where `HashLen` is the output length (in bytes) of the Hash.
#' @param hash A PRF implementation (HMAC) to use. Accepts character name matching the algorithm
#'   name or OID available in `algorithm_list`.
#'
#' @return A list with classes `hkdf_result` and `rkdf_result` containing:
#'   * `key`: raw vector with `len` bytes OKM,
#'   * `algorithm`: the string `"hkdf"`,
#'   * `parameters`: an object of class `hkdf_parameters` with fields `salt`, `len`, `info` and
#'        `hash`
#'   * `timestamp`: UTC timestamp string.
#'
#' @details
#' This implementation follows RFC 5869. Important notes:
#' * If `salt` is omitted, it is replaced with `0x00` repeated `HashLen` times (per RFC).
#' * The function enforces the RFC limit: `len <= 255 * HashLen`.
#'
#' @examples
#' # using a named PRF (friendly name must be registered in algorithm_list)
#' res <- rkdf_kdf_hkdf(NULL, "input-key", "context", 32, "hmac_sha256")
#' cat(res$key)
#'
#' @export
rkdf_kdf_hkdf <- function(salt, ikm, info, len, hash) {

  check_hmac_func(hash, "hash")
  h_up <- .normalized(hash)
  if (h_up %in% algorithm_list$oid) {
    algo <- hash
    hash <- get(oid_to_name(hash))
  } else if (h_up %in% algorithm_list$frdly_name) {
    algo <- name_to_oid(h_up)
    hash <- get(h_up)
  } else if (h_up %in% algorithm_list$short_name) {
    algo <- name_to_oid(h_up)
    hash <- get(short_to_name(h_up))
  } else {
    ck_fail(hash, "hash", "Unable to map requested HMAC-Hash function.")
  }
  hash_len <- oid_to_len(algo)
  if (hash_len <= 0L)
    # Defensive check: oid_to_len should never return 0 or negative, but we keep this
    # as a sanity check in case the algorithm_list data is corrupted
    rkdf_stop("Invalid hash length.",
              "This should never occur - please report as a bug.")

  check_string_or_raw(salt, "salt", TRUE)
  salt <- makeStringRaw(salt)
  if (length(salt) == 0) {
    salt <- raw(hash_len)
  }

  check_string_or_raw(ikm, "ikm")
  ikm <- makeStringRaw(ikm)

  check_string_or_raw(info, "info")
  info <- makeStringRaw(info)

  check_positive_integer(len, "len")
  if (len > 255L * hash_len) {
    ck_fail(len, "len", "Requested output length exceeds 255 * HashLen.")
  }

  prk <- hkdf_extract(salt, ikm, hash)
  if (length(prk) < hash_len) {
    # By construction this should never occur. We still check just in case.
    rkdf_stop("The key obtained from extract is not long enough.",
              "This should never occur - please report as a bug.")
  }

  okm <- hkdf_expand(prk, info, len, hash)

  ts <- strftime(Sys.time(), "%Y-%m-%dT%H:%M:%SZ", tz="UTC")

  params <- list(salt = salt,
                 len = len,
                 info = info,
                 hash = algo)
  params <- structure(params, class = c("hkdf_parameters", class(params)))

  structure(list(key = okm,
                 algorithm = "hkdf",
                 parameters = params,
                 timestamp = ts),
            class = c("hkdf_result", "rkdf_result"))
}
