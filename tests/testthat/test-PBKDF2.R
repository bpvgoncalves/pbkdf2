# PBKDF2-HMAC-SHA1 -----------------------------------------------------------------------
# SHA-1 IETF RFC 6070 test vectors: various iteration counts, dkLen=hlen-HMAC-SHA-1=20
test_that("HMAC-SHA1: iterations", {
    expect_equal(
        PBKDF2("password", "salt", 20, prf=HMAC_SHA1, iterations=1),
        wkb::hex2raw("0c60c80f 961f0e71 f3a9b524 af601206  2fe037a6")
    )
    expect_equal(
        PBKDF2("password", "salt", 20, prf=HMAC_SHA1, iterations=2),
        wkb::hex2raw("ea6c014d c72d6f8c cd1ed92a ce1d41f0  d8de8957")
    )
    expect_equal(
        PBKDF2("password", "salt", 20, prf=HMAC_SHA1, iterations=4096),
        wkb::hex2raw("4b007901 b765489a bead49d9 26f721d0  65a429c1")
    )
})

# SHA-1 IETF RFC 6070 test vectors: longer password and salt, and with special characters; also dkLen != hlen
test_that("HMAC-SHA1: pw salt dkLen", {
    expect_equal(
        PBKDF2("passwordPASSWORDpassword", "saltSALTsaltSALTsaltSALTsaltSALTsalt", 25,
               prf=HMAC_SHA1, iterations=4096),
        wkb::hex2raw(paste(
            "3d2eec4f e41c849b 80c8d836 62c0e44a  8b291a96 4cf2f070 38"
        ))
    )
    pass0word  <- c(charToRaw("pass"), as.raw(0x00), charToRaw("word"))
    sa0lt  <- c(charToRaw("sa"), as.raw(0x00), charToRaw("lt"))
    expect_equal(
        PBKDF2(pass0word, sa0lt, 16, prf=HMAC_SHA1, iterations=4096),
        wkb::hex2raw("56fa6aa7 5548099d cc37d7f0 3425e0c3")
    )
})

# SHA-1 suite from GIT Anti-weakpasswords/PBKDF2-Test-Vectors, iterations <= 10000
test_that("HMAC-SHA1: PBKDF2 can handle tests from pool", {
  df_tests <- read.csv("../doc/PBKDF2-HMAC-Various_Test_Vectors-SHA1_small.csv")
  for (row in 1:nrow(df_tests)) {
    test <- df_tests[row,]
    result <- PBKDF2(test$Password, test$Salt, test$Outputbytes, test$Iterations, HMAC_SHA1)
    expect_equal(result, wkb::hex2raw(test$SHA.1.0xResultInHex))
  }
})


# PBKDF2-HMAC-SHA2 ---------------------------------------------------------------------
# SHA2-224 suite from GIT Anti-weakpasswords/PBKDF2-Test-Vectors, iterations <= 10000
test_that("HMAC-SHA2-224: PBKDF2 can handle tests from pool", {
  df_tests <- read.csv("../doc/PBKDF2-HMAC-Various_Test_Vectors-SHA224_small.csv")
  for (row in 1:nrow(df_tests)) {
    test <- df_tests[row,]
    result <- PBKDF2(test$Password, test$Salt, test$Outputbytes, test$Iterations, HMAC_SHA2_224)
    expect_equal(result, wkb::hex2raw(test$SHA.224.0xResultInHex))
  }
})

test_that("HMAC-SHA2-256: PBKDF2 can handle adhoc tests and tests from pool", {

  # Test various iteration counts, dkLen=hlen-HMAC-SHA-256=32
  expect_equal(
    PBKDF2("password", "salt", 32, iterations=1),
    wkb::hex2raw("120fb6cf fcf8b32c 43e72252 56c4f837  a86548c9 2ccc3548 0805987c b70be17b")
  )
  expect_equal(
    PBKDF2("password", "salt", 32, iterations=2),
    wkb::hex2raw("ae4d0c95 af6b46d3 2d0adff9 28f06dd0  2a303f8e f3c251df d6e2d85a 95474c43")
  )
  expect_equal(
    PBKDF2("password", "salt", 32, iterations=4096),
    wkb::hex2raw("c5e478d5 9288c841 aa530db6 845c4c8d  962893a0 01ce4e11 a4963873 aa98134a")
  )

  # Test varying length password and salt, and with special characters; also dkLen != hlen
  expect_equal(
    PBKDF2("passwordPASSWORDpassword", "saltSALTsaltSALTsaltSALTsaltSALTsalt", 40, iterations=4096),
    wkb::hex2raw(paste(
      "348c89db cbd32b2f 32d814b8 116e84cf  2b17347e bc180018 1c4e2a1f b8dd53e1",
      "c635518c 7dac47e9"
    ))
  )
  pass0word  <- c(charToRaw("pass"), as.raw(0x00), charToRaw("word"))
  sa0lt  <- c(charToRaw("sa"), as.raw(0x00), charToRaw("lt"))
  expect_equal(
    PBKDF2(pass0word, sa0lt, 16, iterations=4096),
    wkb::hex2raw("89b69d05 16f82989 3c696226 650a8687")
  )
  expect_equal(
    PBKDF2("passwd", "salt", 128, iterations=1),
    wkb::hex2raw(paste(
      "55ac046e 56e3089f ec1691c2 2544b605  f9418521 6dde0465 e68b9d57 c20dacbc",
      "49ca9ccc f179b645 991664b3 9d77ef31  7c71b845 b1e30bd5 09112041 d3a19783",
      "c294e850 150390e1 160c34d6 2e9665d6  59ae49d3 14510fc9 8274cc79 68196810",
      "4b8f8923 7e69b2d5 49111868 658be62f  59bd715c ac44a114 7ed5317c 9bae6b2a"
    ))
  )
  expect_equal(
    PBKDF2("Password", "NaCl", 128, iterations=80000),
    wkb::hex2raw(paste(
      "4ddcd8f6 0b98be21 830cee5e f22701f9  641a4418 d04c0414 aeff0887 6b34ab56",
      "a1d425a1 22583354 9adb841b 51c9b317  6a272bde bba1d078 478f62b3 97f33c8d",
      "62aae85a 11cdde82 9d89cb6f fd1ab0e6  3a981f87 47d2f2f9 fe587416 5c83c168",
      "d2eed1d2 d5ca4052 dec2be57 15623da0  19b8c0ec 87dc36aa 751c38f9 893d15c3"
    ))
  )

  # SHA-256 suite from GIT Anti-weakpasswords/PBKDF2-Test-Vectors, iterations <= 10000
  df_tests <- read.csv("../doc/PBKDF2-HMAC-Various_Test_Vectors-SHA256_small.csv")
  for (row in 1:nrow(df_tests)) {
    test <- df_tests[row,]
    result <- PBKDF2(test$Password, test$Salt, test$Outputbytes, test$Iterations)
    expect_equal(result, wkb::hex2raw(test$SHA.256.0xResultInHex))
  }
  for (row in 1:nrow(df_tests)) {
    test <- df_tests[row,]
    result <- PBKDF2(test$Password, test$Salt, test$Outputbytes, test$Iterations, HMAC_SHA2_256)
    expect_equal(result, wkb::hex2raw(test$SHA.256.0xResultInHex))
  }
})

# SHA-384 suite from GIT Anti-weakpasswords/PBKDF2-Test-Vectors, iterations <= 10000
test_that("HMAC-SHA2-384: PBKDF2 can handle tests from pool", {
  df_tests <- read.csv("../doc/PBKDF2-HMAC-Various_Test_Vectors-SHA384_small.csv")
  for (row in 1:nrow(df_tests)) {
    test <- df_tests[row,]
    result <- PBKDF2(test$Password, test$Salt, test$Outputbytes, test$Iterations, HMAC_SHA2_384)
    expect_equal(result, wkb::hex2raw(test$SHA.384.0xResultInHex))
  }
})

# SHA-512 suite from GIT Anti-weakpasswords/PBKDF2-Test-Vectors, iterations <= 10000
test_that("HMAC-SHA2-512: PBKDF2 can handle tests from small pool", {
  df_tests <- read.csv("../doc/PBKDF2-HMAC-Various_Test_Vectors-SHA512_small.csv")
  for (row in 1:nrow(df_tests)) {
    test <- df_tests[row,]
    result <- PBKDF2(test$Password, test$Salt, test$Outputbytes, test$Iterations, HMAC_SHA2_512)
    expect_equal(result, wkb::hex2raw(test$SHA.512.0xResultInHex))
  }
})

test_that("HMAC-SHA2-*: PBKDF2 can handle tests from full pool", {

  skip_on_cran()
  skip_on_ci()

  df_tests <- read.csv("../doc/PBKDF2-HMAC-Various_Test_Vectors-SHA224_all.csv")
  for (row in 1:nrow(df_tests)) {
    test <- df_tests[row,]
    if (test$Iterations > 100000) next # These will take too long to test
    result <- PBKDF2(test$Password, test$Salt, test$Outputbytes, test$Iterations, HMAC_SHA2_224)
    expect_equal(result, wkb::hex2raw(test$SHA.224.0xResultInHex))
  }

  df_tests <- read.csv("../doc/PBKDF2-HMAC-Various_Test_Vectors-SHA256_all.csv")
  for (row in 1:nrow(df_tests)) {
    test <- df_tests[row,]
    if (test$Iterations > 100000) next # These will take too long to test
    result <- PBKDF2(test$Password, test$Salt, test$Outputbytes, test$Iterations)
    expect_equal(result, wkb::hex2raw(test$SHA.256.0xResultInHex))
  }

  df_tests <- read.csv("../doc/PBKDF2-HMAC-Various_Test_Vectors-SHA384_all.csv")
  for (row in 1:nrow(df_tests)) {
    test <- df_tests[row,]
    if (test$Iterations > 100000) next # These will take too long to test
    result <- PBKDF2(test$Password, test$Salt, test$Outputbytes, test$Iterations, HMAC_SHA2_384)
    expect_equal(result, wkb::hex2raw(test$SHA.384.0xResultInHex))
  }

  df_tests <- read.csv("../doc/PBKDF2-HMAC-Various_Test_Vectors-SHA512_all.csv")
  for (row in 1:nrow(df_tests)) {
    test <- df_tests[row,]
    if (test$Iterations > 100000) next # These will take too long to test
    result <- PBKDF2(test$Password, test$Salt, test$Outputbytes, test$Iterations, HMAC_SHA2_512)
    expect_equal(result, wkb::hex2raw(test$SHA.512.0xResultInHex))
  }
})
