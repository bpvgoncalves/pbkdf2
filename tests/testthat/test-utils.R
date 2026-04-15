test_that("helpers work", {

  expect_silent(check_string_or_raw("abc", "x"))
  expect_silent(check_string_or_raw(raw(5), "x"))
  expect_silent(check_string_or_raw(NULL, "x", TRUE))
  expect_error(check_string_or_raw(1, "x"))
  expect_error(check_string_or_raw(c("a", "b"), "x"))
  expect_error(check_string_or_raw(NULL, "x"))
  expect_error(check_string_or_raw(NA, "x", TRUE))
  expect_error(check_string_or_raw("fran\xE7ais", "x"))

  expect_equal(makeStringRaw("A"), charToRaw("A"))
  expect_equal(makeStringRaw(NULL), raw(0))
  expect_error(makeStringRaw(NA))

  expect_error(name_to_oid("invalid_name"))
  expect_error(short_to_name("Not Short"))
  expect_error(oid_to_name("1.2.3.4.5.6.7.8.9.0"))
})
