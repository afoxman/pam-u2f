/*
 * Copyright 2025 Adam Foxman
 *
 * MIT License
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the “Software”),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense, 
 * and/or sell copies of the Software, and to permit persons to whom the 
 * Software is furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR 
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, 
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING 
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 */

#ifndef CRYPT_H
#define CRYPT_H


#include <stdbool.h>

#include "log.h"

#define HMAC_SALT_LENGTH 32

bool generate_hmac_salt(
  const log_t *log,
  unsigned char *hmac_salt);

bool encrypt_password(
  const log_t *log,
  const char *username,
  const unsigned char *credential_id_ptr,
  size_t credential_id_len,
  const unsigned char *hmac_salt,
  const unsigned char *hmac_secret_ptr,
  size_t hmac_secret_len,
  const char *password,
  char **encrypted_password);

bool get_hmac_salt_from_encrypted_password(
  const log_t *log,
  const char *encrypted_password,
  unsigned char *hmac_salt);

bool decrypt_password(
  const log_t *log,
  const char *username,
  const unsigned char *credential_id_ptr,
  size_t credential_id_len,
  const unsigned char *hmac_secret,
  size_t hmac_secret_length,
  const char *encrypted_password,
  char **password);

bool update_encrypted_password(
  const log_t *log,
  const char *old_password,
  const char *new_password,
  const char *username,
  const unsigned char *credential_id_ptr,
  size_t credential_id_len,
  const char *old_encrypted_password,
  char **new_encrypted_password);

#endif /* CRYPT_H */
