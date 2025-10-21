
#' makeStringRaw
#'
#' Convert a UTF-8 string to raw bytes.
#'
#' @param obj  the UTF-8 string to be converted
#'
#' @keywords internal
#'
makeStringRaw <- function(obj) {
  result <- obj;
  if (!is.raw(obj)) {
    if (is.character(obj)) {
      if (!validUTF8(obj)) stop("Input to makeStringRaw() must be a valid UTF-8 string or raw bytes.")
      result <- charToRaw(obj)
    }
  }
  return(result)
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
