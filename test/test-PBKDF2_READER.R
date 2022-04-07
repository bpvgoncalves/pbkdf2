source("../PBKDF2/R/R6/pbkdf2.R", CHDIR=TRUE)
library(testthat)
library(wkb)

# PBKDF2-HMAC-SHA-256 ---------------------------------------------------------------------

# Test various iteration counts, dkLen=hlen-HMAC-SHA-256=32
test_that("PBKDF2_READER can handle basic operations", {

    reader <- PBKDF2_READER$new("password", "salt", iterations=1)
    expect_is(reader, "PBKDF2_READER")
    expect_equal(
        reader$read(32),
        hex2raw("120fb6cf fcf8b32c 43e72252 56c4f837  a86548c9 2ccc3548 0805987c b70be17b")
    )

    reader <- PBKDF2_READER$new("password", "salt", iterations=2)
    expect_is(reader, "PBKDF2_READER")
    expect_equal(
        reader$read(32),
        hex2raw("ae4d0c95 af6b46d3 2d0adff9 28f06dd0  2a303f8e f3c251df d6e2d85a 95474c43")
    )

    reader <- PBKDF2_READER$new("password", "salt", iterations=4096)
    expect_is(reader, "PBKDF2_READER")
    expect_equal(
        reader$read(32),
        hex2raw("c5e478d5 9288c841 aa530db6 845c4c8d  962893a0 01ce4e11 a4963873 aa98134a")
    )
})

# Test varying length password and salt, and with special characters; also dkLen != hlen
test_that("PBKDF2_READER can handle pw, salt, dkLen variations", {

    reader <- PBKDF2_READER$new("passwordPASSWORDpassword",
                                "saltSALTsaltSALTsaltSALTsaltSALTsalt",
                                iterations=4096)
    expect_is(reader, "PBKDF2_READER")
    expect_equal(
        reader$read(40),
        hex2raw(paste(
            "348c89db cbd32b2f 32d814b8 116e84cf  2b17347e bc180018 1c4e2a1f b8dd53e1",
            "c635518c 7dac47e9"
        ))
    )

    pass0word  <- c(charToRaw("pass"), as.raw(0x00), charToRaw("word"))
    sa0lt  <- c(charToRaw("sa"), as.raw(0x00), charToRaw("lt"))
    reader <- PBKDF2_READER$new(pass0word, sa0lt, iterations=4096)
    expect_is(reader, "PBKDF2_READER")
    expect_equal(
        reader$read(16),
        hex2raw("89b69d05 16f82989 3c696226 650a8687")
    )

    reader <- PBKDF2_READER$new("passwd", "salt", iterations=1)
    expect_is(reader, "PBKDF2_READER")
    expect_equal(
        reader$read(128),
        hex2raw(paste(
            "55ac046e 56e3089f ec1691c2 2544b605  f9418521 6dde0465 e68b9d57 c20dacbc",
            "49ca9ccc f179b645 991664b3 9d77ef31  7c71b845 b1e30bd5 09112041 d3a19783",
            "c294e850 150390e1 160c34d6 2e9665d6  59ae49d3 14510fc9 8274cc79 68196810",
            "4b8f8923 7e69b2d5 49111868 658be62f  59bd715c ac44a114 7ed5317c 9bae6b2a"
        ))
    )

    reader <- PBKDF2_READER$new("Password", "NaCl", iterations=80000)
    expect_is(reader, "PBKDF2_READER")
    expect_equal(
        reader$read(128),
        hex2raw(paste(
            "4ddcd8f6 0b98be21 830cee5e f22701f9  641a4418 d04c0414 aeff0887 6b34ab56",
            "a1d425a1 22583354 9adb841b 51c9b317  6a272bde bba1d078 478f62b3 97f33c8d",
            "62aae85a 11cdde82 9d89cb6f fd1ab0e6  3a981f87 47d2f2f9 fe587416 5c83c168",
            "d2eed1d2 d5ca4052 dec2be57 15623da0  19b8c0ec 87dc36aa 751c38f9 893d15c3"
        ))
    )
})

# SHA-1 IETF RFC 6070 test vectors: various iteration counts, dkLen=hlen-HMAC-SHA-1=20
test_that("PBKDF2_READER can handle basic operations", {
    reader <- PBKDF2_READER("password", "salt", prf=HMAC_SHA_1, iterations=1)
    expect_is(reader, "PBKDF2_READER")
    expect_equal(
        reader$read(20),
        hex2raw("0c60c80f 961f0e71 f3a9b524 af601206  2fe037a6")
    )
    reader <- PBKDF2_READER("password", "salt", prf=HMAC_SHA_1, iterations=2)
    expect_is(reader, "PBKDF2_READER")
    expect_equal(
        reader$read(20),
        hex2raw("ea6c014d c72d6f8c cd1ed92a ce1d41f0  d8de8957")
    )
    reader <- PBKDF2_READER("password", "salt", prf=HMAC_SHA_1, iterations=4096)
    expect_is(reader, "PBKDF2_READER")
    expect_equal(
        reader$read(20),
        hex2raw("4b007901 b765489a bead49d9 26f721d0  65a429c1")
    )
})

# SHA-1 IETF RFC 6070 test vectors: longer password and salt, and with special characters; also dkLen != hlen
test_that("PBKDF2_READER can handle pw, salt, dkLen variations", {
    reader <- PBKDF2_READER("passwordPASSWORDpassword",
                     "saltSALTsaltSALTsaltSALTsaltSALTsalt",
                     prf=HMAC_SHA_1, iterations=4096)
    expect_is(reader, "PBKDF2_READER")
    expect_equal(
        reader$read(25),
        hex2raw(paste(
            "3d2eec4f e41c849b 80c8d836 62c0e44a  8b291a96 4cf2f070 38"
        ))
    )
    pass0word  <- c(charToRaw("pass"), as.raw(0x00), charToRaw("word"))
    sa0lt  <- c(charToRaw("sa"), as.raw(0x00), charToRaw("lt"))
    reader <- PBKDF2_READER(pass0word, sa0lt, prf=HMAC_SHA_1, iterations=4096)
    expect_is(reader, "PBKDF2_READER")
    expect_equal(
        reader$read(16),
        hex2raw("56fa6aa7 5548099d cc37d7f0 3425e0c3")
    )
})
