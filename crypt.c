/*
 * Copyright (C) 2025 Yubico AB - See COPYING
 */

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <string.h>

#include "b64.h"
#include "crypt.h"
#include "util.h"

#define EP_FMT "salt=%s|iv=%s|ep=%s"

#define CALLMSG(f,m) \
  do { \
    if (!(f)) { \
      log_msg(log, "error: %s: %s (%d)\n", (m), strerror(errno), errno); \
      goto err; \
    } \
  } while (0)

#define CALL(f) CALLMSG(f, #f)

#define CALL_OSSL(f) \
  do { \
    if ((long)(f) < 1) { \
      log_ossl_error(log, #f); \
      goto err; \
    } \
  } while (0)

static void log_ossl_error(const debug_log_t *log, const char *api) {
  unsigned long error;
  char error_string[512];

  error = ERR_get_error();
  ERR_error_string_n(error, error_string, sizeof(error_string));
  log_msg(log, "error: %s: %s (%lu)\n", api, error_string, error);
}

bool generate_ep_params(const debug_log_t *log, ep_params_t *ep_params) {
  bool result = false;
  CALL_OSSL(RAND_bytes(ep_params->hmac_salt, sizeof(ep_params->hmac_salt)));
  CALL_OSSL(RAND_bytes(ep_params->iv, sizeof(ep_params->iv)));
  result = true;
err:
  return result;
}

bool encrypt_password(const debug_log_t *log, const ep_params_t *ep_params,
                      const unsigned char* hmac_secret, size_t hmac_secret_len,
                      const char *password, unsigned char **ep, size_t *ep_len) {
  bool result = false;
  int password_len;
  size_t encrypted_size;
  unsigned char *encrypted = NULL;
  size_t encrypted_len = 0;
  EVP_CIPHER_CTX *ctx = NULL;
  int count;

  if (hmac_secret_len != HMAC_SECRET_SIZE) {
    log_msg(log, "error: invalid hmac_secret_len %zu, expected %d\n", hmac_secret_len, HMAC_SECRET_SIZE);
    goto err;
  }
  password_len = (int)strlen(password);

  encrypted_size = sizeof(ep_params->iv) + (((password_len + 15) / 16) * 16);
  CALL(encrypted = malloc(encrypted_size));

  CALL_OSSL(ctx = EVP_CIPHER_CTX_new());
  CALL_OSSL(EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, hmac_secret, ep_params->iv));
  CALL_OSSL(EVP_EncryptUpdate(ctx, encrypted, &count, (const unsigned char *)password, password_len));
  encrypted_len += count;
  CALLMSG(encrypted_len <= encrypted_size, "encryption buffer overflow");

  CALL_OSSL(EVP_EncryptFinal_ex(ctx, encrypted + encrypted_len, &count));
  encrypted_len += count;
  CALLMSG(encrypted_len <= encrypted_size, "encryption buffer overflow");

  *ep = encrypted;
  *ep_len = encrypted_len;
  encrypted = NULL;
  result = true;

err:
  free(encrypted);
  if (ctx != NULL)
    EVP_CIPHER_CTX_free(ctx);

  return result;
}

char *serialize_ep(const debug_log_t *log, const ep_params_t *ep_params,
                   const unsigned char *ep, size_t ep_len) {
  char *b64_salt = NULL;
  char *b64_iv = NULL;
  char *b64_ep = NULL;
  char *formatted = NULL;

  CALL(b64_encode(ep_params->hmac_salt, sizeof(ep_params->hmac_salt), &b64_salt));
  CALL(b64_encode(ep_params->iv, sizeof(ep_params->iv), &b64_iv));
  CALL(b64_encode(ep, ep_len, &b64_ep));
  CALL(formatted = format(EP_FMT, b64_salt, b64_iv, b64_ep));

err:
  free(b64_ep);
  free(b64_iv);
  free(b64_salt);

  return formatted;
}

/*
// https://wiki.openssl.org/index.php/EVP_Symmetric_Encryption_and_Decryption

int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
            unsigned char *iv, unsigned char *plaintext)
{
    sscanf(arg, "max_devices=%u", &cfg->max_devs);


    EVP_CIPHER_CTX *ctx;

    int len;

    int plaintext_len;

    if(!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors();

    if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
        handleErrors();

    if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
        handleErrors();
    plaintext_len = len;

    if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len))
        handleErrors();
    plaintext_len += len;

    EVP_CIPHER_CTX_free(ctx);

    return plaintext_len;
}
*/
