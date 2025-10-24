df <- data.frame(oid = NA, frdly_name = NA)

# HMAC - Algorithms ----
df <- rbind(df, list("1.3.6.1.5.5.8.1.2",       "HMAC_SHA1"))

df <- rbind(df, list("1.2.840.113549.2.8",      "HMAC_SHA2_224"))
df <- rbind(df, list("1.2.840.113549.2.9",      "HMAC_SHA2_256"))
df <- rbind(df, list("1.2.840.113549.2.10",     "HMAC_SHA2_384"))
df <- rbind(df, list("1.2.840.113549.2.11",     "HMAC_SHA2_512"))

df <- rbind(df, list("2.16.840.1.101.3.4.2.13", "HMAC_SHA3_224"))
df <- rbind(df, list("2.16.840.1.101.3.4.2.14", "HMAC_SHA3_256"))
df <- rbind(df, list("2.16.840.1.101.3.4.2.15", "HMAC_SHA3_384"))
df <- rbind(df, list("2.16.840.1.101.3.4.2.16", "HMAC_SHA3_512"))

# Save data for internal use
algorithm_list <- na.omit(df)
usethis::use_data(algorithm_list, internal = TRUE, overwrite = TRUE)
