# MNEMONIC WRONG INPUTS -----------------------------------------------------------------------
test_that("rkdf_mnemonic_to_words() fails with wrong entropy type", {

  expect_error(rkdf_mnemonic_to_words("not-a-raw-vector"), "Entropy must be a raw vector")
  expect_error(rkdf_mnemonic_to_words(123), "Entropy must be a raw vector")
  expect_error(rkdf_mnemonic_to_words(NULL), "Entropy must be a raw vector")
  expect_error(rkdf_mnemonic_to_words(TRUE), "Entropy must be a raw vector")

})

test_that("rkdf_mnemonic_to_words() fails with wrong entropy length", {

  expect_error(rkdf_mnemonic_to_words(raw(15)), "Entropy must be 16, 20, 24, 28, or 32 bytes")
  expect_error(rkdf_mnemonic_to_words(raw(17)), "Entropy must be 16, 20, 24, 28, or 32 bytes")
  expect_error(rkdf_mnemonic_to_words(raw(33)), "Entropy must be 16, 20, 24, 28, or 32 bytes")
  expect_error(rkdf_mnemonic_to_words(raw(0)), "Entropy must be 16, 20, 24, 28, or 32 bytes")

})

test_that("rkdf_mnemonic_to_seed() fails with invalid mnemonic", {

  expect_error(rkdf_mnemonic_to_seed(NULL), "mnemonic")
  expect_error(rkdf_mnemonic_to_seed(TRUE), "mnemonic")
  expect_error(rkdf_mnemonic_to_seed(123), "mnemonic")

})

test_that("rkdf_mnemonic_to_seed() fails with invalid passphrase", {

  expect_error(rkdf_mnemonic_to_seed("valid words", TRUE), "passphrase")
  expect_error(rkdf_mnemonic_to_seed("valid words", 123), "passphrase")
  expect_error(rkdf_mnemonic_to_seed("valid words", c("multiple", "passphrases")), "passphrase")

})

test_that("rkdf_mnemonic_to_seed() fails with empty mnemonic", {

  expect_error(rkdf_mnemonic_to_seed(""), "Mnemonic cannot be empty")

})

test_that("rkdf_mnemonic_validate() fails with invalid input", {

  expect_error(rkdf_mnemonic_validate(NULL), "mnemonic")
  expect_error(rkdf_mnemonic_validate(TRUE), "mnemonic")
  expect_error(rkdf_mnemonic_validate(123), "mnemonic")

})


# MNEMONIC VALIDATION TESTS -------------------------------------------------------------------
test_that("rkdf_mnemonic_validate() returns FALSE for wrong word count", {

  expect_false(rkdf_mnemonic_validate(c("abandon")))
  expect_false(rkdf_mnemonic_validate(c("abandon", "ability")))
  expect_false(rkdf_mnemonic_validate(rep("abandon", 11)))
  expect_false(rkdf_mnemonic_validate(rep("abandon", 13)))
  expect_false(rkdf_mnemonic_validate(rep("abandon", 25)))

})

test_that("rkdf_mnemonic_validate() returns FALSE for invalid words", {

  expect_false(rkdf_mnemonic_validate(c("notaword", rep("abandon", 11))))
  expect_false(rkdf_mnemonic_validate(c(rep("abandon", 11), "invalid")))
  expect_false(rkdf_mnemonic_validate(c(rep("abandon", 6), "notaword", rep("abandon", 5))))

})

test_that("rkdf_mnemonic_validate() returns FALSE for invalid checksum", {

  # First, verify we have a valid mnemonic
  entropy <- as.raw(c(0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
                      0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff))
  words <- rkdf_mnemonic_to_words(entropy)
  expect_true(rkdf_mnemonic_validate(words))

  # Now modify it to create an invalid checksum
  bad_words <- c(words[-1], "abandon")
  expect_false(rkdf_mnemonic_validate(bad_words))

})


# MNEMONIC TO WORDS TEST VECTORS --------------------------------------------------------------
test_that("rkdf_mnemonic_to_words() produces correct words for test vector", {

  entropy <- as.raw(c(
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
    0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff
  ))

  result <- rkdf_mnemonic_to_words(entropy)

  expect_type(result, "character")
  expect_equal(length(result), 12L)

  expect_equal(result, c(
    "abandon", "math", "mimic", "master", "filter", "design",
    "carbon", "crystal", "rookie", "group", "knife", "young"
  ))

})

test_that("rkdf_mnemonic_to_words() works with 20 bytes (160 bits)", {

  entropy <- as.raw(c(
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
    0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
    0x00, 0x11, 0x22, 0x33
  ))

  result <- rkdf_mnemonic_to_words(entropy)

  expect_equal(length(result), 15L)

})

test_that("rkdf_mnemonic_to_words() works with 24 bytes (192 bits)", {

  entropy <- as.raw(c(
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
    0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77
  ))

  result <- rkdf_mnemonic_to_words(entropy)

  expect_equal(length(result), 18L)

})

test_that("rkdf_mnemonic_to_words() works with 28 bytes (224 bits)", {

  entropy <- as.raw(c(
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
    0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
    0x88, 0x99, 0xaa, 0xbb
  ))

  result <- rkdf_mnemonic_to_words(entropy)

  expect_equal(length(result), 21L)

})

test_that("rkdf_mnemonic_to_words() works with 32 bytes (256 bits)", {

  entropy <- as.raw(c(
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
    0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
    0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff
  ))

  result <- rkdf_mnemonic_to_words(entropy)

  expect_equal(length(result), 24L)

})

test_that("rkdf_mnemonic_to_words() validates roundtrip", {

  entropy <- as.raw(c(
    0x1c, 0xb7, 0x2f, 0x90, 0xc1, 0xc5, 0xd4, 0x61,
    0x01, 0x37, 0xf5, 0xcd, 0x6f, 0x34, 0x7c, 0x39
  ))

  words <- rkdf_mnemonic_to_words(entropy)
  expect_true(rkdf_mnemonic_validate(words))

})


# MNEMONIC TO SEED TEST VECTORS ---------------------------------------------------------------
test_that("rkdf_mnemonic_to_seed() produces 64-byte seed", {

  words <- c("abandon", "math", "mimic", "master", "filter", "design",
              "carbon", "crystal", "rookie", "group", "knife", "young")

  result <- rkdf_mnemonic_to_seed(words)

  expect_true(inherits(result, "pbkdf2_result"))
  expect_true(inherits(result$masterkey, "raw"))
  expect_equal(length(result$masterkey), 64L)

})

test_that("rkdf_mnemonic_to_seed() works with string input", {

  words_str <- "abandon math mimic master filter design carbon crystal rookie group knife young"

  result <- rkdf_mnemonic_to_seed(words_str)

  expect_true(inherits(result, "pbkdf2_result"))
  expect_equal(length(result$masterkey), 64L)

})

test_that("rkdf_mnemonic_to_seed() uses correct parameters", {

  words <- c("abandon", "math", "mimic", "master", "filter", "design",
              "carbon", "crystal", "rookie", "group", "knife", "young")

  result <- rkdf_mnemonic_to_seed(words)

  expect_equal(result$parameters$iter, 2048L)
  expect_equal(result$parameters$len, 64L)

})

test_that("rkdf_mnemonic_to_seed() handles passphrase", {

  words <- c("abandon", "math", "mimic", "master", "filter", "design",
              "carbon", "crystal", "rookie", "group", "knife", "young")

  result_empty <- rkdf_mnemonic_to_seed(words, "")
  result_pass <- rkdf_mnemonic_to_seed(words, "my passphrase")

  expect_false(identical(result_empty$masterkey, result_pass$masterkey))

})

test_that("rkdf_mnemonic_to_seed() roundtrip works", {

  entropy <- as.raw(c(
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
    0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff
  ))

  words <- rkdf_mnemonic_to_words(entropy)
  expect_true(rkdf_mnemonic_validate(words))

  seed <- rkdf_mnemonic_to_seed(words)
  expect_equal(length(seed$masterkey), 64L)

})


# MNEMONIC VALIDATE ROUNDTRIP TESTS ----------------------------------------------------------
test_that("rkdf_mnemonic_validate() accepts valid 12-word mnemonic", {

  words <- c("bronze", "ride", "tomorrow", "logic", "front", "correct",
             "age", "wrong", "sniff", "keen", "business", "infant")

  expect_true(rkdf_mnemonic_validate(words))

})

test_that("rkdf_mnemonic_validate() accepts valid 15-word mnemonic", {

  entropy <- as.raw(c(
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
    0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
    0x00, 0x11, 0x22, 0x33
  ))

  words <- rkdf_mnemonic_to_words(entropy)

  expect_true(rkdf_mnemonic_validate(words))

})

test_that("rkdf_mnemonic_validate() accepts valid 24-word mnemonic", {

  entropy <- as.raw(c(
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
    0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
    0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff
  ))

  words <- rkdf_mnemonic_to_words(entropy)

  expect_true(rkdf_mnemonic_validate(words))

})

test_that("rkdf_mnemonic_validate() works with string input", {

  words_str <- "bronze ride tomorrow logic front correct age wrong sniff keen business infant"

  expect_true(rkdf_mnemonic_validate(words_str))

})

test_that("rkdf_mnemonic_validate() returns FALSE for modified checksum", {

  words <- c("bronze", "ride", "tomorrow", "logic", "front", "correct",
             "age", "wrong", "sniff", "keen", "business", "infant")

  expect_true(rkdf_mnemonic_validate(words))

  words_modified <- c(words[-1], "abandon")
  expect_false(rkdf_mnemonic_validate(words_modified))

})

test_that("rkdf_mnemonic_validate() returns FALSE for shuffled words", {

  words <- c("bronze", "ride", "tomorrow", "logic", "front", "correct",
             "age", "wrong", "sniff", "keen", "business", "infant")

  words_shuffled <- sample(words)

  expect_false(rkdf_mnemonic_validate(words_shuffled))

})


# BIP39 SPECIFICATION TEST VECTORS -----------------------------------------------------------
test_that("BIP39 test vector: 128-bit entropy", {

  entropy <- as.raw(c(
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
  ))

  words <- rkdf_mnemonic_to_words(entropy)

  expect_equal(words, c(
    "abandon", "abandon", "abandon", "abandon", "abandon",
    "abandon", "abandon", "abandon", "abandon", "abandon",
    "abandon", "about"
  ))

  expect_true(rkdf_mnemonic_validate(words))

})

test_that("BIP39 256-bit entropy produces valid mnemonic", {

  entropy <- as.raw(c(
    0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f,
    0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f,
    0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f,
    0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f
  ))

  words <- rkdf_mnemonic_to_words(entropy)

  expect_equal(length(words), 24L)
  expect_true(rkdf_mnemonic_validate(words))

})

test_that("BIP39 test vector with passphrase produces different seed", {

  words <- c("abandon", "math", "mimic", "master", "filter", "design",
             "carbon", "crystal", "rookie", "group", "knife", "young")

  seed_empty <- rkdf_mnemonic_to_seed(words, "")$masterkey
  seed_trezor <- rkdf_mnemonic_to_seed(words, "TREZOR")$masterkey

  expect_false(identical(seed_empty, seed_trezor))

})
