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

bool decrypt_password(const debug_log_t *log, const ep_params_t *ep_params,
                      const unsigned char *hmac_secret, size_t hmac_secret_len,
                      const unsigned char *ep, size_t ep_len,
                      char **password) {
  bool result = false;
  size_t decrypted_size;
  unsigned char *decrypted = NULL;
  size_t decrypted_len = 0;
  EVP_CIPHER_CTX *ctx = NULL;
  int count;

  if (hmac_secret_len != HMAC_SECRET_SIZE) {
    log_msg(log, "error: invalid hmac_secret_len %zu, expected %d\n", hmac_secret_len, HMAC_SECRET_SIZE);
    goto err;
  }

  decrypted_size = (((ep_len + 15) / 16) * 16) + 1;
  CALL(decrypted = malloc(decrypted_size));

  CALL_OSSL(ctx = EVP_CIPHER_CTX_new());
  CALL_OSSL(EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, hmac_secret, ep_params->iv));
  CALL_OSSL(EVP_DecryptUpdate(ctx, decrypted, &count, ep, (int)ep_len));
  decrypted_len += count;
  CALLMSG(decrypted_len < decrypted_size, "decryption buffer overflow");

  CALL_OSSL(EVP_DecryptFinal_ex(ctx, decrypted + decrypted_len, &count));
  decrypted_len += count;
  CALLMSG(decrypted_len < decrypted_size, "decryption buffer overflow");
  decrypted[decrypted_len] = '\0';

  *password = (char*)decrypted;
  decrypted = NULL;
  result = true;

err:
  if (decrypted != NULL) {
    explicit_bzero(decrypted, decrypted_size);
    free(decrypted);
  }
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




struct str {
  const char *ptr;
  size_t len;
};

typedef struct str str_t;

#define STRFMT "%.*s"
#define STRVA(s) (int)s.len, s.ptr

#define STRINIT(s) { .ptr = s, .len = sizeof(s)-1 }

str_t str_get(const char *);
int str_compare(str_t, str_t);
size_t str_split(str_t, const char, str_t *, size_t);



// static const str_t str_empty = { .ptr = NULL, .len = 0 };

str_t str_get(const char *p) {
  str_t s = { .ptr = p, .len = strlen(p) };
  return s;
}

int str_compare(str_t left, str_t right) {
  if (left.len < right.len)
    return -1;
  if (left.len > right.len)
    return 1;
  return strncmp(left.ptr, right.ptr, left.len);
}

size_t str_split(str_t s, const char delimiter, str_t *tokens, size_t tokens_len) {
  size_t token_count = 0;

  const char *start = s.ptr;
  const char *end = s.ptr + s.len;
  const char *cur = start;
  while (token_count < tokens_len && cur < end) {
    if (delimiter == *cur) {
      tokens[token_count].ptr = start;
      tokens[token_count].len = cur - start;
      token_count++;

      start = cur + 1;
    }
  }

  if (token_count < tokens_len && cur > start) {
    tokens[token_count].ptr = start;
    tokens[token_count].len = cur - start;
    token_count++;
  }

  return token_count;
}

// str_t str_substr_len(str_t s, size_t offset, size_t length) {
//   // Bound the substring using the input, carefully avoiding overflows.
//   if (offset > s.len)
//     offset = s.len;
//   if (length > s.len - offset)
//     length = s.len - offset;

//   // Modify the input, turning it into the substring.
//   s.ptr += offset;
//   s.len = length;
//   return s;
// }

// str_t str_substr(str_t s, size_t offset) {
//   return str_substr_len(s, offset, SIZE_MAX);
// }

// str_t str_find_first(str_t s, char delimiter) {
//   for (size_t i = 0; i < s.len; i++) {
//     const char ch = s.ptr[i];
//     if (ch == delimiter)
//       return str_substr(s, i);
//     if (ch == '\0')
//       return str_empty;
//   }
//   return str_empty;
// }





#define EP_FIELD_COUNT 3

bool parse_named_field(const debug_log_t *, str_t, str_t, str_t *);
bool parse_named_field_base64(const debug_log_t *, str_t, str_t, unsigned char **, size_t *);
bool parse_named_field_base64_copy(const debug_log_t *, str_t, str_t, unsigned char *, size_t);





static const str_t str_ep_key_salt = STRINIT("salt");
static const str_t str_ep_key_iv = STRINIT("iv");
static const str_t str_ep_key_ep = STRINIT("ep");

bool parse_named_field(const debug_log_t *log, str_t field, str_t name, str_t *value) {
  str_t tokens[2];
  size_t count;
  
  count = str_split(field, '=', tokens, 2);
  if (count != 2) {
    log_msg(log, "error: parse_named_field("STRFMT"): field is not in key=value form -- "STRFMT"\n", STRVA(name), STRVA(field));
    return false;
  }

  if (0 != str_compare(name, tokens[0])) {
    log_msg(log, "error: parse_named_field("STRFMT"): got unexpected key "STRFMT"\n", STRVA(name), STRVA(tokens[0]));
    return false;
  }

  *value = tokens[1];
  return true;
}

bool parse_named_field_base64(const debug_log_t *log, str_t field, str_t name, unsigned char **value, size_t *value_len) {
  bool result = false;
  str_t s;

  CALL(parse_named_field(log, field, name, &s));
  CALL_OSSL(b64_decode(s.ptr, s.len, (void **)value, value_len));
  result = true;

err:
  return result;
}

bool parse_named_field_base64_copy(const debug_log_t *log, str_t field, str_t name, unsigned char *value, size_t value_len) {
  bool result = false;
  unsigned char *data = NULL;
  size_t data_len;

  CALL(parse_named_field_base64(log, field, name, &data, &data_len));
  if (data_len != value_len) {
    log_msg(log, "error: parse_named_field_base64_copy("STRFMT"): got %zu bytes, expected %zu bytes\n", STRVA(name), data_len, value_len);
    goto err;
  }
  memcpy(value, data, value_len);
  result = true;

err:
  free(data);
  return result;
}


bool deserialize_ep(const debug_log_t *log, const char* ep_serialized,
                    ep_params_t *ep_params, unsigned char** ep, size_t* ep_len) {
  bool result = false;
  size_t count;
  str_t fields[EP_FIELD_COUNT];
  unsigned char *ep_value = NULL;
  size_t ep_value_len;

  count = str_split(str_get(ep_serialized), '|', fields, EP_FIELD_COUNT);
  if (count != EP_FIELD_COUNT) {
    log_msg(log, "error: encrypted password is missing fields -- found %zu, expected %d\n", count, EP_FIELD_COUNT);
    goto err;
  }
  CALL(parse_named_field_base64_copy(log, fields[0], str_ep_key_salt, ep_params->hmac_salt, sizeof(ep_params->hmac_salt)));
  CALL(parse_named_field_base64_copy(log, fields[1], str_ep_key_iv, ep_params->iv, sizeof(ep_params->iv)));
  CALL(parse_named_field_base64(log, fields[2], str_ep_key_ep, &ep_value, &ep_value_len));

  *ep = ep_value;
  ep_value = NULL;
  *ep_len = ep_value_len;
  result = true;

err:
  free(ep_value);
  return result;
}
