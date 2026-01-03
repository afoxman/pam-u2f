/*
 * Copyright (C) 2026 Yubico AB - See COPYING
 */

#ifndef CRYPT_H
#define CRYPT_H

#include <stdbool.h>

#include "log.h"
#include "util.h"

#define HMAC_SALT_LENGTH 32

bool generate_hmac_salt(const log_t *log, unsigned char *hmac_salt);

bool encrypt_password(const log_t *log, const char *username,
  bytes_t cred_id, const unsigned char *hmac_salt, bytes_t hmac_secret,
  const char *password, char **encrypted_password);

bool get_hmac_salt_from_encrypted_password(const log_t *log,
  const char *encrypted_password, unsigned char *hmac_salt);

bool decrypt_password(const log_t *log, const char *username, bytes_t cred_id,
  bytes_t hmac_secret, const char *encrypted_password, char **password);

bool update_encrypted_password(const log_t *log, const char *old_password,
  const char *new_password, const char *username, bytes_t cred_id,
  const char *old_encrypted_password, char **new_encrypted_password);

#endif /* CRYPT_H */
