

hkdf_extract <- function(salt, ikm, fun) {
  if (length(salt) == 0) salt = raw(32)
  fun(salt, ikm)

}

hkdf_expand <- function(prk, info, len, fun) {

  t <- raw(0)
  okm <- raw(0)
  i <- 0

  while (length(okm) < len) {

    i <- i + 1
    t <- fun(prk, c(t, info, as.raw(i)))
    okm <- c(okm, t)
  }
  okm[1:len]
}


rkdf_kdf_hkdf <- function(salt, ikm, info, len, fun) {

  prk <- hkdf_extract(salt, ikm, fun)

  hkdf_expand(prk, info, len, fun)

}
