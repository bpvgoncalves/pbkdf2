df <- data.frame(oid = NA, short_name = NA, frdly_name = NA, len = NA)

# HMAC - Algorithms ----
df <- rbind(df, list("1.3.6.1.5.5.8.1.2",       "SHA1",     "HMAC_SHA1",     20L))

df <- rbind(df, list("1.2.840.113549.2.8",      "SHA224",   "HMAC_SHA224",   28L))
df <- rbind(df, list("1.2.840.113549.2.9",      "SHA256",   "HMAC_SHA256",   32L))
df <- rbind(df, list("1.2.840.113549.2.10",     "SHA384",   "HMAC_SHA384",   48L))
df <- rbind(df, list("1.2.840.113549.2.11",     "SHA512",   "HMAC_SHA512",   64L))

df <- rbind(df, list("2.16.840.1.101.3.4.2.13", "SHA3_224", "HMAC_SHA3_224", 28L))
df <- rbind(df, list("2.16.840.1.101.3.4.2.14", "SHA3_256", "HMAC_SHA3_256", 32L))
df <- rbind(df, list("2.16.840.1.101.3.4.2.15", "SHA3_384", "HMAC_SHA3_384", 48L))
df <- rbind(df, list("2.16.840.1.101.3.4.2.16", "SHA3_512", "HMAC_SHA3_512", 64L))

# Save data for internal use
algorithm_list <- na.omit(df)
usethis::use_data(algorithm_list, internal = TRUE, overwrite = TRUE)
