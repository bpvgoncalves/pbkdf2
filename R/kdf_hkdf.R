
hkdf_extract <- function(salt, ikm, hash) {

  # RFC 5869 §2.2
  # PRK = HMAC-Hash(salt, IKM)
  hash(salt, ikm)
}


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
    rkdf_stop("Unable to determine HashLen.",
              "Underlying HMAC implementation returned zero-length output.")

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
    rkdf_stop("The key obtained from extract is not long enough.")
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
