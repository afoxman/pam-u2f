/*
 * Copyright (C) 2025 Yubico AB - See COPYING
 */

#include <openssl/err.h>
#include <openssl/evp.h>
#include <string.h>

#include "b64.h"
#include "crypt.h"
#include "util.h"

#define EP_FMT "salt=%s|iv=%s|ep=%s"


static void log_ossl_error(const debug_log_t *log, const char *api) {
  unsigned long error;
  char error_string[512];

  error = ERR_get_error();
  ERR_error_string_n(error, error_string, sizeof(error_string));
  log_msg(log, "error: %s: %s (%lu)\n", api, error_string, error);
}


char *encrypt_password(const debug_log_t *log,
                     const void *hmac_salt, size_t hmac_salt_len, 
                     const void *iv, size_t iv_len,
                     const void *key, size_t key_len,
                     const char *password) {
  int password_len;
  size_t encrypted_size;
  unsigned char *encrypted = NULL;
  size_t encrypted_len = 0;
  EVP_CIPHER_CTX *ctx = NULL;
  int count;
  char *b64_salt = NULL;
  char *b64_iv = NULL;
  char *b64_ep = NULL;
  char *ep = NULL;

  if (iv_len != 16) {
    log_msg(log, "error: initialization vector length must be 16 bytes for AES-256-CBC\n");
    goto err;
  }
  if (key_len != 32) {
    log_msg(log, "error: key length must be 32 bytes for AES-256-CBC\n");
    goto err;
  }

  password_len = (int)strlen(password);

  encrypted_size = iv_len + (((password_len + 15) / 16) * 16);
  encrypted = malloc(encrypted_size);
  if (!encrypted) {
    log_msg(log, "error: failed to allocate encrypted password buffer\n");
    goto err;
  }

  if (!(ctx = EVP_CIPHER_CTX_new())) {
    log_ossl_error(log, "EVP_CIPHER_CTX_new");
    goto err;
  }

  if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) {
    log_ossl_error(log, "EVP_EncryptInit_ex(EVP_aes_256_cbc)");
    goto err;
  }

  if (1 != EVP_EncryptUpdate(ctx, encrypted, &count, (const unsigned char *)password, password_len)) {
    log_ossl_error(log, "EVP_EncryptUpdate");
    goto err;    
  }
  encrypted_len += count;
  if (encrypted_len > encrypted_size) {
    log_msg(log, "error: encryption buffer overflow\n");
    goto err;
  }

  if (1 != EVP_EncryptFinal_ex(ctx, encrypted + encrypted_len, &count)) {
    log_ossl_error(log, "EVP_EncryptFinal_ex");
    goto err;    
  }
  encrypted_len += count;
  if (encrypted_len > encrypted_size) {
    log_msg(log, "error: encryption buffer overflow\n");
    goto err;
  }

  if (!b64_encode(hmac_salt, hmac_salt_len, &b64_salt) ||
      !b64_encode(iv, iv_len, &b64_iv) ||
      !b64_encode(encrypted, encrypted_len, &b64_ep)) {
    log_msg(log, "error: failed to base64-encode encrypted password data\n");
    goto err;
  }

  if (!(ep = format(EP_FMT, b64_salt, b64_iv, b64_ep))) {
    log_msg(log, "error: failed to allocate formatted output\n");
    goto err;
  }

err:
  free(b64_ep);
  free(b64_iv);
  free(b64_salt);
  if (encrypted != NULL) {
    explicit_bzero(encrypted, encrypted_len);
    free(encrypted);
  }
  if (ctx != NULL)
    EVP_CIPHER_CTX_free(ctx);

  return ep;
}
