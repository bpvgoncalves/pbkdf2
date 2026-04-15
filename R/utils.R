
#' makeStringRaw
#' Convert a string to raw bytes.
#' @keywords internal
makeStringRaw <- function(x) {

  if (is.null(x))
    return(raw(0))

  if (is.raw(x))
    return(x)

  if (is.character(x)) {

    # Must be scalar character
    if (length(x) != 1L || is.na(x))
      stop("makeStringRaw(): character input must be length-1 and non-NA")

    # Normalize and ensure valid UTF-8
    utf8 <- enc2utf8(x)
    if (!validUTF8(utf8))
      stop("makeStringRaw(): invalid UTF-8 input")
    return(charToRaw(utf8))
  }

  stop("makeStringRaw(): unexpected type (internal error)")
}



#' uintToRaw
#'
#' Convert an unsigned integer from R numeric to its big-endian binary form.
#' Used to convert the index argument of the f function into the required
#' 4-byte vector to append to the salt.
#'
#' @param num     the number, which must be positive with no fractional part
#' @param minLen  the minimum number of bytes in the result (default: 4)
#'
#' @keywords internal
#'
uintToRaw <- function(num, minLen=4) {
  if(0 > num) stop(paste(num, "is not positive."))
  if(0 != num %% 1) stop(paste(num, "is not an integer."))
  raw <- raw()
  rem <- num
  repeat {
    lo <- rem %% 256
    rem <- rem %/% 256
    raw <- c(as.raw(lo), raw)
    if (rem == 0 && minLen <= length(raw)) break
  }
  return(raw)
}


#' @keywords internal
# Normalize an identifier for case-insensitive comparison (friendly/short names)
.normalized <- function(x) {
  if (is.null(x)) return(NULL)
  toupper(as.character(x))
}


#' @keywords internal
name_to_oid <- function(name) {

  if (!is.character(name) || length(name) != 1L)
    rkdf_stop("name_to_oid(): 'name' must be a single string")

  if (name %in% algorithm_list$frdly_name) {
    matches <- which(.normalized(algorithm_list$frdly_name) == .normalized(name))
  } else {
    matches <- which(.normalized(algorithm_list$short_name) == .normalized(name))
  }

  if (length(matches) == 0L)
    rkdf_stop(sprintf("Unknown friendly name: %s", name))

  if (length(matches) > 1L)
    rkdf_stop(sprintf("Ambiguous friendly name: %s", name))

  as.character(algorithm_list$oid[matches])
}


#' @keywords internal
oid_to_name <- function(oid) {

  if (!is.character(oid) || length(oid) != 1L)
    rkdf_stop("oid_to_name(): 'oid' must be a single string")

  matches <- which(algorithm_list$oid == oid)
  if (length(matches) == 0L)
    rkdf_stop(sprintf("Unknown OID: %s", oid))
  if (length(matches) > 1L)
    rkdf_stop(sprintf("Ambiguous OID: %s", oid))

  as.character(algorithm_list$frdly_name[matches])
}


#' @keywords internal
oid_to_len <- function(oid) {

  if (!is.character(oid) || length(oid) != 1L)
    rkdf_stop("oid_to_name(): 'oid' must be a single string")

  matches <- which(algorithm_list$oid == oid)
  if (length(matches) == 0L)
    rkdf_stop(sprintf("Unknown OID: %s", oid))
  if (length(matches) > 1L)
    rkdf_stop(sprintf("Ambiguous OID: %s", oid))

  as.integer(algorithm_list$len[matches])
}


#' @keywords internal
short_to_name <- function(short) {

  if (!is.character(short) || length(short) != 1L)
    rkdf_stop(sprintf("short_to_name(): 'short' must be a single string"))

  matches <- which(.normalized(algorithm_list$short_name) == .normalized(short))
  if (length(matches) == 0L)
    rkdf_stop(sprintf("Unknown short name: ", short, call. = FALSE))
  if (length(matches) > 1L)
    rkdf_stop(sprintf("Ambiguous short name: ", short, call. = FALSE))

  as.character(algorithm_list$frdly_name[matches])
}


rkdf_stop <- function(err_msg, add_msg = NULL) {

  msg <- paste("\n\u274c", err_msg)
  if (!is.null(add_msg) && length(add_msg) == 1)
    msg <- paste(msg, "\n\U0001f4a1", add_msg)

  stop(msg, call. = FALSE)
}


#' @keywords internal
ck_fail <- function(value, name, msg) {
  rkdf_stop(sprintf("Invalid parameter `%s`: %s", name, deparse(value)),
            msg)
}


#' @keywords internal
check_positive_integer <- function(x, name) {

  if (length(x) != 1L || !is.numeric(x))
    ck_fail(x, name, "Must be a scalar integer.")

  if (!is.finite(x) || x <= 0 || x != as.integer(x))
    ck_fail(x, name, "Must be a strictly positive integer.")

  invisible()
}



#' @keywords internal
check_string_or_raw <- function(x, name, allow_null = FALSE) {

  if (is.null(x)) {
    if (allow_null) return(invisible())
    ck_fail(x, name, "Must not be NULL.")
  }

  if (is.raw(x))
    return(invisible())

  if (is.character(x)) {
    if (length(x) != 1L)
      ck_fail(x, name, "Character input must be of length 1.")
    if (!validUTF8(x))
      ck_fail(x, name, "Character input must be valid UTF-8.")
    return(invisible())
  }

  msg <- "Must be raw or character."
  if (allow_null)
    msg <- "Must be NULL, raw or character."
  ck_fail(x, name, msg)
}


#' @keywords internal
check_hmac_func <- function(x, name) {

  if (!is.character(x) || length(x) != 1L)
    ck_fail(x, name, "Must be a single character string.")

  # uppercase normalization outside, but basic sanity check here
  if (!nzchar(x))
    ck_fail(x, name, "Must not be empty string.")

  val <- as.character(x)
  # exact OID match or case-insensitive friendly or short name match
  if (val %in% as.character(algorithm_list$oid) ||
      .normalized(val) %in% .normalized(algorithm_list$frdly_name) ||
      .normalized(val) %in% .normalized(algorithm_list$short_name)) {
    return(invisible())
  }

  invisible()
}
