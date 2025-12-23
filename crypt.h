/*
 * Copyright (C) 2025 Yubico AB - See COPYING
 */

#ifndef CRYPT_H
#define CRYPT_H

#include <stdbool.h>

#include "debug.h"

#define HMAC_SALT_SIZE 32
#define HMAC_SECRET_SIZE 32
#define INIT_VECTOR_SIZE 16

struct ep_params {
  unsigned char hmac_salt[HMAC_SALT_SIZE];
  unsigned char iv[INIT_VECTOR_SIZE];
};

typedef struct ep_params ep_params_t;

bool generate_ep_params(const debug_log_t *log, ep_params_t *ep_params);

bool encrypt_password(const debug_log_t *log, const ep_params_t *ep_params,
                      const unsigned char* hmac_secret, size_t hmac_secret_len,
                      const char *password,
                      unsigned char **ep, size_t *ep_len);

char *serialize_ep(const debug_log_t *log, const ep_params_t *ep_params,
                   const unsigned char *ep, size_t ep_len);

#endif /* CRYPT_H */
