/*
 * Copyright (C) 2025 Yubico AB - See COPYING
 */

#ifndef CRYPT_H
#define CRYPT_H

#include "debug.h"

char *encrypt_password(const debug_log_t *log, 
                       const void* hmac_salt, size_t hmac_salt_len, 
                       const void *iv, size_t iv_len,
                       const void *key, size_t key_len,
                       const char *password);

#endif /* CRYPT_H */
