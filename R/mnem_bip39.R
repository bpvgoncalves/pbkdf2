#' @keywords internal
bip39_normalize <- function(x) {
  enc2utf8(x)
}

rkdf_mnemonic_to_words <- function(entropy) {

  if (!is.raw(entropy))
    stop("Entropy must be a raw vector.")

  entropy_len <- length(entropy)
  check_entropy_len <- entropy_len %in% c(16L, 20L, 24L, 28L, 32L)
  if (!check_entropy_len)
    stop("Entropy must be 16, 20, 24, 28, or 32 bytes (128, 160, 192, 224, or 256 bits).")

  # Compute SHA256 checksum (first ENT/8 bytes)
  hash <- openssl::sha256(entropy)
  checksum_len <- entropy_len / 4  # 4 bits per byte of entropy

  # Append checksum bits to entropy bits
  # rawToBits is LSB-first; reverse each byte to get MSB-first
  entropy_bits <- as.integer(rawToBits(entropy))
  entropy_msb <- unlist(lapply(split(entropy_bits, rep(seq_len(length(entropy_bits)/8L), each=8L)), rev))

  hash_bits <- as.integer(rawToBits(hash))
  hash_msb <- unlist(lapply(split(hash_bits, rep(seq_len(length(hash_bits)/8L), each=8L)), rev))
  checksum_bits <- hash_msb[seq_len(checksum_len)]
  combined <- c(entropy_msb, checksum_bits)

  # Slice into 11-bit words (each maps to an index 0-2047)
  n_words <- length(combined) / 11L

  words <- character(n_words)
  for (i in seq_len(n_words)) {
    start <- (i - 1L) * 11L + 1L
    bits <- combined[start:(start + 10L)]
    idx <- sum(bits * c(1024L, 512L, 256L, 128L, 64L, 32L, 16L, 8L, 4L, 2L, 1L))
    words[i] <- bip39_wordlist[[idx + 1L]]
  }

  words
}

rkdf_mnemonic_to_seed <- function(mnemonic, passphrase = "") {

  # Normalize inputs — handle both character vector and single string
  if (is.character(mnemonic) && length(mnemonic) > 1) {
    mnemonic <- paste(mnemonic, collapse = " ")
  }
  check_string_or_raw(mnemonic, "mnemonic")

  if (is.character(passphrase) && length(passphrase) > 1) {
    passphrase <- paste(passphrase, collapse = " ")
  }
  check_string_or_raw(passphrase, "passphrase")

  mnemonic <- bip39_normalize(mnemonic)
  passphrase <- bip39_normalize(passphrase)

  if (!nzchar(mnemonic))
    stop("Mnemonic cannot be empty.")

  salt <- bip39_normalize(paste0("mnemonic", passphrase))

  # BIP39 uses PBKDF2-HMAC-SHA512, 2048 iterations, 64-byte output
  # We delegate to our existing PBKDF2 implementation
  rkdf_kdf_pbkdf2(mnemonic, charToRaw(salt), 64L, iterations = 2048L, prf = HMAC_SHA512)
}

rkdf_mnemonic_validate <- function(mnemonic) {

  # Normalize and split — handle both character vector and single string
  if (is.character(mnemonic) && length(mnemonic) > 1) {
    mnemonic <- paste(mnemonic, collapse = " ")
  }
  # Now mnemonic is either a single string or single-element character vector
  check_string_or_raw(mnemonic, "mnemonic")
  mnemonic <- strsplit(mnemonic, "\\s+")[[1]]
  n_words <- length(mnemonic)

  # Valid word counts: 12, 15, 18, 21, 24
  if (!n_words %in% c(12L, 15L, 18L, 21L, 24L))
    return(FALSE)

  # Look up indices (binary search via match)
  indices <- match(mnemonic, bip39_wordlist) - 1L  # Convert to 0-based
  if (any(is.na(indices)))
    return(FALSE)

  # Reconstruct the bit stream
  n_bits <- n_words * 11L
  bits <- integer(n_bits)
  for (i in seq_along(indices)) {
    idx <- indices[i]
    start <- (i - 1L) * 11L + 1L
    for (j in 0:10) {
      bits[start + 10L - j] <- (idx %/% (2^j)) %% 2L
    }
  }

  # Entropy is the first ENT bits, checksum is the remaining CS bits
  # ENT = n_words * 11 - CS, CS = ENT / 32
  # Simplify: total_bits = 32 * m where m = n_words / 3
  # ENT = 32 * m * 32 / 33, CS = 32 * m / 33
  m <- n_words / 3L
  entropy_bits  <- n_words * 11L * 32L / 33L
  checksum_bits <- n_words * 11L / 33L

  entropy_len <- as.integer(entropy_bits / 8L)

  ent_bits <- bits[seq_len(entropy_bits)]
  cs_bits  <- bits[(entropy_bits + 1L):n_bits]

  # Build entropy bytes
  entropy <- raw(entropy_len)
  for (i in seq_len(entropy_len)) {
    start <- (i - 1L) * 8L + 1L
    byte <- sum(ent_bits[start:(start + 7L)] * c(128L, 64L, 32L, 16L, 8L, 4L, 2L, 1L))
    entropy[i] <- as.raw(byte)
  }

  # Compute expected checksum
  hash <- openssl::sha256(entropy)
  hash_bits <- as.integer(rawToBits(hash))
  msb_first <- unlist(lapply(split(hash_bits, rep(seq_len(length(hash_bits)/8L), each=8L)), rev))
  expected_cs_bits <- msb_first[seq_len(checksum_bits)]

  # Compare
  identical(as.integer(cs_bits), as.integer(expected_cs_bits))
}
