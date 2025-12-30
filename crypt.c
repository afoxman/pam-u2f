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

 /* 
 * Cryptographic Algorithms for Secure Password Storage and Update
 * Using a FIDO2 Authenticator
 *
 * === Summary ===
 * 
 * The purpose of this library is to assist with "logging a user in" via their
 * FIDO2 authenticator (e.g. Yubikey V5+).
 * 
 * To log in, a user's password must be provided to the operating system via 
 * the PAM authentication stack. Existing PAM modules, like the GNOME keyring,
 * use the password to unlock the user's secret store automatically.
 * 
 * A user's password is not stored in a typical system, so this system must 
 * store it. Further, the password must be encrypted and bound to a specific
 * FIDO2 authenticator, to ensure it cannot be used by anyone other than the
 * owning user. This is done using the FIDO2 hmac-secret extension.
 * 
 * The system must react to password changes for the user, updating the
 * encrypted copy of the password so that "login" continues to work without
 * interruption. This must be done using the established chain of trust,
 * without relying on the user to (again) interact with their FIDO2
 * authenticator.
 *
 * === HMAC secret ===
 *
 * The HMAC secret comes from the FIDO2 authenticator, via the hmac-secret
 * extension. The hardware must support this extension in order to make use
 * of this "login" workflow.
 * 
 * The secret is bound to the authenticator, establishing a chain of trust.
 * We provide the authenticator a credential id and a salt (both randomly 
 * generated). The authenticator combines these with its own secret key, 
 * which never leaves the device. It then emits the bound secret.
 * 
 * The secret is used to derive a 256-bit symmetric key which encrypts the
 * user's password. We use a NIST-compliant two-step HMAC key derivation 
 * algorithm, ensuring sufficient entropy to guard against compromise:
 * 
 * https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-56Cr2.pdf
 * (pages 17-24)
 * 
 * NIST compliance requires that additional information be fed into the
 * derivation algorithm, further binding the key to the specific user, system,
 * and operation being performed. The following fields are included:
 * 
 *   - "u2f-local-authentication-v1"
 *       A static label identifying V1 of this cryptographic process.
 *   - User name (string)
 *   - Credential ID (bytes)
 *   - HMAC key derivation salt (bytes)
 *   - Encryption key initiialization vector (bytes)
 *   - 0x01 0x00 (bytes)
 *       Length of a V1 derived key, which is 256 bytes.
 *
 * === Encryption and Decryption ===
 * 
 * Encryption and decryption is done using a 256-bit symmetric key with the
 * AES GCM (Galois/Counter Mode) algorithm. GCM provides both encryption and
 * signature verification, which prevents disclosure and tampering.
 * 
 * AES GCM is a NIST-approved algorithm:
 * 
 * https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf
 * 
 * === Storage ===
 * 
 * Once the password has been encrypted and signed, it will be stored, along
 * with all of the parameters used to produce it from the HMAC secret. This
 * data can be stored on insecure storage. Disclosure gives no advantage, as
 * the root key material (HMAC secret) is protected by the authenticator.
 * 
 * This design assumes disclosure. Parameters such as salt and initialization
 * vector are used to increase complexity, making compromise unlikely.
 * Storing them in the clear gives no advantage to an attacker.
 * 
 * === Password Updates ===
 * 
 * When a password change occurs for a user, the new password must be
 * encrypted and updated in the system to keep the "login" flow operational.
 * To do this, the HMAC secret is needed, yet it is only accessible via the
 * FIDO2 authenticator.
 * 
 * So the HMAC secret itself must be encrypted and stored, alongside the
 * password. Encryption is done with the user's password, binding it to
 * the user. No other user can access it.
 * 
 * The password is used to derive a 256-bit symmetric key with a 
 * NIST-compliant algorithm for password-based key derivation:
 * 
 * https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-132.pdf
 * 
 * The derived key is used to encrypt and decrypt the HMAC secret. The
 * encrypted HMAC secret and its encrypted parameters are stored next to
 * the encrypted password. All of this data is safe to store in the clear.
 * 
 * When the password change occurs, PAM delivers both the current and new 
 * passwords to all modules. This system uses the current password to decrypt
 * the HMAC secret, and the new password to (re)encrypt it. 
 * 
 * This is a well-known process, and is how the GNOME keyring (among others)
 * handles password changes.
 * 
 * NOTE: When the superuser resets a password, only the new password is
 *       provided. This means the HMAC secret cannot be decrypted, and the
 *       encrypted password cannot be updated.
 *
 *       While this breaks the "login" flow, it is a well-known drawback
 *       of the default password architecture in Unix systems. It impacts all
 *       PAM-based modules. For example, the GNOME keyring loses automatic
 *       unlock on login, and requires user intervention to be repaired. If
 *       the user does not have the old password, the keyring is lost.
 */

#include <openssl/core.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/rand.h>
#include <openssl/types.h>

#include <string.h>

#include "b64.h"
#include "crypt.h"


#define CALLMSG(f,m) \
  do { \
    if (!(f)) { \
      log_error(log, "%s: error %d: %s", (m), errno, strerror(errno)); \
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

static void log_ossl_error(const log_t *log, const char *api) {
  unsigned long error;
  char error_string[512];

  error = ERR_get_error();
  ERR_error_string_n(error, error_string, sizeof(error_string));
  log_error(log, "%s: error %lu: %s", api, error, error_string);
}


#define V1_DOMAIN_STR                "u2f-local-authentication-v1"
#define V1_DOMAIN_LEN                (sizeof(V1_DOMAIN_STR) - 1)


#define AES_256_GCM_KEY_LENGTH       32
#define AES_256_GCM_KEY_LENGTH_BITS  (AES_256_GCM_KEY_LENGTH * 8)

#define PASSWORD_KEY_V1_ITERATIONS   (1 * 1000 * 1000)


typedef struct hmac_secret_key_derivation_params_v1
{
  unsigned char hmac_salt[HMAC_SALT_LENGTH];
} hmac_secret_key_derivation_params_v1_t;

typedef struct 
{
  unsigned char pbkdf_salt[32];
  size_t pbkdf_iterations;
} password_key_derivation_params_v1_t;

typedef struct 
{
  unsigned char aes_iv[12];
  unsigned char aes_tag[16];
} aes_256_gcm_params_v1_t;

typedef struct 
{
  hmac_secret_key_derivation_params_v1_t kdp;
  aes_256_gcm_params_v1_t cp;
} encrypted_password_params_v1_t;

typedef struct 
{
  password_key_derivation_params_v1_t kdp;
  aes_256_gcm_params_v1_t cp;
} encrypted_hmac_secret_params_v1_t;

typedef struct
{
  unsigned char data[AES_256_GCM_KEY_LENGTH];
} aes_256_gcm_key_t;

typedef struct
{
  unsigned char *ptr;
  size_t len;
} bytes_t;

typedef struct
{
  const char *ptr;
  size_t len;
} str_t;


/*
 * String and Byte Arrays
 */

#define BYTESINIT(p,l)  { .ptr = p, .len = l }

#define STRINIT(s)      { .ptr = s, .len = sizeof(s)-1 }
#define STRFMT          "%.*s"
#define STRVA(s)        (int)s.len, s.ptr

static bytes_t bytes_get(unsigned char *ptr, size_t len) 
{
  bytes_t b = { .ptr = ptr, .len = len };
  return b;
}

ATTRIBUTE_FORMAT(printf, 1, 2)
static char *format(const char *fmt, ...) 
{
  va_list ap_scan, ap_format;
  size_t count;
  char *out = NULL;

  va_start(ap_scan, fmt);
  va_copy(ap_format, ap_scan);
  count = vsnprintf(NULL, 0, fmt, ap_scan);
  out = malloc(count + 1);
  if (out)
    vsnprintf(out, count + 1, fmt, ap_format);
  va_end(ap_scan);
  va_end(ap_format);

  return out;
}

static str_t str_get(const char *p) 
{
  str_t s = { .ptr = p, .len = p ? strlen(p) : 0 };
  return s;
}

static size_t str_split(
  str_t s, 
  const char delimiter, 
  str_t *tokens, size_t tokens_len) 
{
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

static int str_compare(str_t left, str_t right) 
{
  if (left.len < right.len)
    return -1;
  if (left.len > right.len)
    return 1;
  return strncmp(left.ptr, right.ptr, left.len);
}


/*
 * Object Management
 */

static bool initialize_aes_256_gcm_params_v1(
  const log_t *log,
  aes_256_gcm_params_v1_t *params) 
{
  CALL_OSSL(RAND_bytes(params->aes_iv, sizeof(params->aes_iv)));
  memset(params->aes_tag, 0, sizeof(params->aes_tag));
  return true;
err:
  return false;
}

static bool initialize_encrypted_password_params_v1(
  const log_t *log,
  const unsigned char *hmac_salt,
  encrypted_password_params_v1_t *params) 
{
  memcpy(params->kdp.hmac_salt, hmac_salt, sizeof(params->kdp.hmac_salt));
  CALL(initialize_aes_256_gcm_params_v1(log, &params->cp));
  return true;
err:
  return false;
}

static bool initialize_encrypted_hmac_secret_params_v1(
  const log_t *log,
  encrypted_hmac_secret_params_v1_t *params) 
{
  CALL_OSSL(RAND_bytes(params->kdp.pbkdf_salt, sizeof(params->kdp.pbkdf_salt)));
  params->kdp.pbkdf_iterations = PASSWORD_KEY_V1_ITERATIONS;
  CALL(initialize_aes_256_gcm_params_v1(log, &params->cp));
  return true;
err:
  return false;
}

static void cleanse_key(aes_256_gcm_key_t *key)
{
  OPENSSL_cleanse(key->data, sizeof(key->data));
}

static void cleanse_and_free_owned_bytes(bytes_t *b)
{
  if (b->ptr) {
    OPENSSL_cleanse(b->ptr, b->len);
    free(b->ptr);
    b->ptr = NULL;
  }
  b->len = 0;
}


/*
 * Key Derivation
 */

static bytes_t copy(bytes_t buffer, const unsigned char *ptr, size_t len) {
  if (buffer.len > 0 && len > 0) {
    if (len > buffer.len)
      len = buffer.len;

    memcpy(buffer.ptr, ptr, len);
    buffer.ptr += len;
    buffer.len -= len;
  }
  return buffer;
}

static bool derive_key_from_hmac_secret(
  const log_t *log,
  const char *username,
  bytes_t credential_id,
  const encrypted_password_params_v1_t *params,
  bytes_t hmac_secret,
  aes_256_gcm_key_t *key)
{
  bool result = false;
  unsigned char info_buffer[1024];
  bytes_t info = { .ptr = info_buffer, .len = sizeof(info_buffer) };
  const size_t aes_256_key_length = AES_256_GCM_KEY_LENGTH_BITS;
  int kdf_mode;
  OSSL_PARAM ossl_params[6];
  size_t params_len = 0;
  EVP_KDF *kdf = NULL;
  EVP_KDF_CTX *ctx = NULL;

  info = copy(info, (const unsigned char *)V1_DOMAIN_STR, V1_DOMAIN_LEN);
  info = copy(info, (const unsigned char *)username, strlen(username));
  info = copy(info, credential_id.ptr, credential_id.len);
  info = copy(info, params->kdp.hmac_salt, sizeof(params->kdp.hmac_salt));
  info = copy(info, params->cp.aes_iv, sizeof(params->cp.aes_iv));
  info = copy(
    info, 
    (const unsigned char *)&aes_256_key_length, 
    sizeof(aes_256_key_length));

  // OpenSSL docs: https://docs.openssl.org/3.0/man7/EVP_KDF-HKDF

  kdf_mode = EVP_KDF_HKDF_MODE_EXTRACT_AND_EXPAND;

  ossl_params[params_len++] = OSSL_PARAM_construct_int(
    OSSL_KDF_PARAM_MODE, &kdf_mode);
  ossl_params[params_len++] = OSSL_PARAM_construct_utf8_string(
    OSSL_KDF_PARAM_DIGEST, SN_sha256, strlen(SN_sha256));
  ossl_params[params_len++] = OSSL_PARAM_construct_octet_string(
    OSSL_KDF_PARAM_SALT, 
    (unsigned char *)params->kdp.hmac_salt, 
    sizeof(params->kdp.hmac_salt));
  ossl_params[params_len++] = OSSL_PARAM_construct_octet_string(
    OSSL_KDF_PARAM_KEY, hmac_secret.ptr, hmac_secret.len);
  ossl_params[params_len++] = OSSL_PARAM_construct_octet_string(
    OSSL_KDF_PARAM_INFO, info_buffer, info.ptr - info_buffer);
  ossl_params[params_len++] = OSSL_PARAM_construct_end();
  CALLMSG(params_len <= sizeof(ossl_params) / sizeof(ossl_params[0]), 
    "OpenSSL parameter overflow");

  CALL_OSSL(kdf = EVP_KDF_fetch(NULL, "HKDF", NULL));
  CALL_OSSL(ctx = EVP_KDF_CTX_new(kdf));
  CALL_OSSL(EVP_KDF_derive(ctx, key->data, sizeof(key->data), ossl_params));
  result = true;

err:
  EVP_KDF_CTX_free(ctx);
  EVP_KDF_free(kdf);

  return result;
}

static bool derive_key_from_password(
  const log_t *log,
  const password_key_derivation_params_v1_t *params,
  const char *password,
  aes_256_gcm_key_t *key)
{
  bool result = false;
  OSSL_PARAM ossl_params[5];
  size_t params_len = 0;
  EVP_KDF *kdf = NULL;
  EVP_KDF_CTX *ctx = NULL;

  // OpenSSL docs: https://docs.openssl.org/3.0/man7/EVP_KDF-PBKDF2

  ossl_params[params_len++] = OSSL_PARAM_construct_utf8_string(
    OSSL_KDF_PARAM_DIGEST, SN_sha256, strlen(SN_sha256));
  ossl_params[params_len++] = OSSL_PARAM_construct_octet_string(
    OSSL_KDF_PARAM_SALT, (unsigned char *)params->pbkdf_salt, sizeof(params->pbkdf_salt));
  ossl_params[params_len++] = OSSL_PARAM_construct_size_t(
    OSSL_KDF_PARAM_ITER, (size_t *)&params->pbkdf_iterations);
  ossl_params[params_len++] = OSSL_PARAM_construct_octet_string(
    OSSL_KDF_PARAM_PASSWORD, (char *)password, strlen(password));
  ossl_params[params_len++] = OSSL_PARAM_construct_end();
  CALLMSG(params_len <= sizeof(ossl_params) / sizeof(ossl_params[0]), 
    "OpenSSL parameter overflow");

  CALL_OSSL(kdf = EVP_KDF_fetch(NULL, "PBKDF2", NULL));
  CALL_OSSL(ctx = EVP_KDF_CTX_new(kdf));
  CALL_OSSL(EVP_KDF_derive(ctx, key->data, sizeof(key->data), ossl_params));
  result = true;

err:
  EVP_KDF_CTX_free(ctx);
  EVP_KDF_free(kdf);

  return result;
}


/*
 * Encryption
 */

static bool encrypt_aes_256_gcm(
  const log_t *log,
  aes_256_gcm_params_v1_t *params,
  const aes_256_gcm_key_t *key,
  bytes_t plaintext,
  bytes_t *ciphertext)
{
  bool result = false;
  EVP_CIPHER_CTX *ctx = NULL;
  int n;
  int length;

  CALL(ciphertext->ptr = malloc(plaintext.len));
  ciphertext->len = plaintext.len;

  CALL_OSSL(ctx = EVP_CIPHER_CTX_new());
  CALL_OSSL(EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL));
  CALL_OSSL(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 
    sizeof(params->aes_iv), NULL));
  CALL_OSSL(EVP_EncryptInit_ex(ctx, NULL, NULL, key->data, params->aes_iv));
  CALL_OSSL(EVP_EncryptUpdate(ctx, ciphertext->ptr, &n, 
    plaintext.ptr, (int)plaintext.len));
  length = n;
  CALLMSG((size_t)length <= ciphertext->len, 
    "encryption buffer overflow (update)");
  CALL_OSSL(EVP_EncryptFinal_ex(ctx, ciphertext->ptr + length, &n));
  length += n;
  CALLMSG((size_t)length <= ciphertext->len, 
    "encryption buffer overflow (final)");
  CALL_OSSL(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 
    sizeof(params->aes_tag), params->aes_tag));
  result = true;

err:
  EVP_CIPHER_CTX_free(ctx);

  if (!result) {
    free(ciphertext->ptr);
    ciphertext->ptr = NULL;
    ciphertext->len = 0;
  }

  return result;
}

static bool decrypt_aes_256_gcm(
  const log_t *log,
  const aes_256_gcm_params_v1_t *params,
  const aes_256_gcm_key_t *key,
  bytes_t ciphertext,
  bytes_t *plaintext)
{
  bool result = false;
  bytes_t out = BYTESINIT(NULL, 0);
  EVP_CIPHER_CTX *ctx = NULL;
  int n;
  int length;

  CALL(out.ptr = malloc(ciphertext.len + 1));
  out.len = ciphertext.len + 1;

  CALL_OSSL(ctx = EVP_CIPHER_CTX_new());
  CALL_OSSL(EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL));
  CALL_OSSL(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 
    sizeof(params->aes_iv), NULL));
  CALL_OSSL(EVP_DecryptInit_ex(ctx, NULL, NULL, key->data, params->aes_iv));
  CALL_OSSL(EVP_DecryptUpdate(ctx, out.ptr, &n, 
    ciphertext.ptr, (int)ciphertext.len));
  length = n;
  CALLMSG((size_t)length < out.len, "decryption buffer overflow (update)");
  CALL_OSSL(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 
    sizeof(params->aes_tag), (unsigned char *)params->aes_tag));
  CALL_OSSL(EVP_DecryptFinal_ex(ctx, out.ptr + length, &n));
  length += n;
  CALLMSG((size_t)length < out.len, "decryption buffer overflow (final)");
  out.ptr[length] = '\0';
  out.len = length;

  *plaintext = out;
  out.ptr = NULL;
  result = true;

err:
  EVP_CIPHER_CTX_free(ctx);
  cleanse_and_free_owned_bytes(&out);

  return result;
}


/*
 * Serialization
 */

#define V1_FIELD_COUNT 10

static const str_t field_v     = STRINIT("v");
static const str_t field_pks   = STRINIT("pks");
static const str_t field_piv   = STRINIT("piv");
static const str_t field_ps    = STRINIT("ps");
static const str_t field_p     = STRINIT("p");
static const str_t field_hsks  = STRINIT("hsks");
static const str_t field_hski  = STRINIT("hski");
static const str_t field_hsiv  = STRINIT("hsiv");
static const str_t field_hss   = STRINIT("hss");
static const str_t field_hs    = STRINIT("hs");

static bool parse_field(
  const log_t *log, 
  str_t field, 
  str_t name, 
  str_t *value)
{
  str_t tokens[2];
  size_t count;
  
  count = str_split(field, '=', tokens, 2);
  if (count != 2) {
    log_error(log, 
              "field not in key=value form: '"STRFMT"'",
              STRVA(field));
    return false;
  }

  if (0 != str_compare(name, tokens[0])) {
    log_error(log, 
              "got unexpected field name '"STRFMT"' (expected '"STRFMT"')",
              STRVA(name), 
              STRVA(tokens[0]));
    return false;
  }

  *value = tokens[1];
  return true;
}

static bool parse_field_b64(
  const log_t *log, 
  str_t field, 
  str_t name, 
  bytes_t *value) 
{
  bool result = false;
  str_t s;

  CALL(parse_field(log, field, name, &s));
  CALL_OSSL(b64_decode(s.ptr, s.len, (void**)&value->ptr, &value->len));
  result = true;

err:
  return result;
}

static bool parse_field_b64_copy(
  const log_t *log, 
  str_t field, 
  str_t name,
  bytes_t value_target) 
{
  bool result = false;
  bytes_t value = { .ptr = NULL, .len = 0 };

  CALL(parse_field_b64(log, field, name, &value));
  if (value.len != value_target.len) {
    log_error(log, 
              "field '"STRFMT"': got %zu bytes, but expected %zu bytes",
              STRVA(name), 
              value.len,
              value_target.len);
    goto err;
  }
  memcpy(value_target.ptr, value.ptr, value_target.len);
  result = true;

err:
  free(value.ptr);
  return result;
}

static bool serialize_encrypted_password(
  const log_t *log,
  const encrypted_password_params_v1_t *password_params,
  bytes_t password_ciphertext,
  const encrypted_hmac_secret_params_v1_t *hmac_secret_params,
  bytes_t hmac_secret_ciphertext,
  char **s)
{
  bool result = false;
  char *pks = NULL;
  char *piv = NULL;
  char *ps = NULL;
  char *p = NULL;
  char *hsks = NULL;
  char *hsiv = NULL;
  char *hss = NULL;
  char *hs = NULL;

  CALL(b64_encode(
    password_params->kdp.hmac_salt, 
    sizeof(password_params->kdp.hmac_salt), 
    &pks));
  CALL(b64_encode(
    password_params->cp.aes_iv, 
    sizeof(password_params->cp.aes_iv), 
    &piv));
  CALL(b64_encode(
    password_params->cp.aes_tag, 
    sizeof(password_params->cp.aes_tag), 
    &ps));
  CALL(b64_encode(
    password_ciphertext.ptr, 
    password_ciphertext.len, 
    &p));
  CALL(b64_encode(
    hmac_secret_params->kdp.pbkdf_salt, 
    sizeof(hmac_secret_params->kdp.pbkdf_salt), 
    &hsks));
  CALL(b64_encode(
    hmac_secret_params->cp.aes_iv, 
    sizeof(hmac_secret_params->cp.aes_iv), 
    &hsiv));
  CALL(b64_encode(
    hmac_secret_params->cp.aes_tag, 
    sizeof(hmac_secret_params->cp.aes_tag), 
    &hss));
  CALL(b64_encode(
    hmac_secret_ciphertext.ptr, 
    hmac_secret_ciphertext.len, 
    &hs));
  CALL(*s = format(
    "v=1|pks=%s|piv=%s|ps=%s|p=%s|hsks=%s|hski=%zu|hsiv=%s|hss=%s|hs=%s",
    pks, piv, ps, p, 
    hsks, hmac_secret_params->kdp.pbkdf_iterations, hsiv, hss, hs));
  result = true;

err:
  free(hs);
  free(hss);
  free(hsiv);
  free(hsks);
  free(p);
  free(ps);
  free(piv);
  free(pks);

  return result;
}

static bool deserialize_encrypted_password(
  const log_t *log,
  const char *s,
  encrypted_password_params_v1_t *password_params,
  bytes_t *password_ciphertext,
  encrypted_hmac_secret_params_v1_t *hmac_secret_params,
  bytes_t *hmac_secret_ciphertext)
{
  bool result = false;
  str_t fields[V1_FIELD_COUNT];
  size_t count;
  str_t v;
  bytes_t pks = BYTESINIT(password_params->kdp.hmac_salt, 
    sizeof(password_params->kdp.hmac_salt));
  bytes_t piv = BYTESINIT(password_params->cp.aes_iv, 
    sizeof(password_params->cp.aes_iv));
  bytes_t ps = BYTESINIT(password_params->cp.aes_tag, 
    sizeof(password_params->cp.aes_tag));
  bytes_t p = BYTESINIT(NULL, 0);
  bytes_t hsks = BYTESINIT(hmac_secret_params->kdp.pbkdf_salt, 
    sizeof(hmac_secret_params->kdp.pbkdf_salt));
  str_t hski;
  long hski_value;
  bytes_t hsiv = BYTESINIT(hmac_secret_params->cp.aes_iv, 
    sizeof(hmac_secret_params->cp.aes_iv));
  bytes_t hss = BYTESINIT(hmac_secret_params->cp.aes_tag, 
    sizeof(hmac_secret_params->cp.aes_tag));
  bytes_t hs = BYTESINIT(NULL, 0);

  count = str_split(str_get(s), '|', fields, V1_FIELD_COUNT);
  if (count != V1_FIELD_COUNT) {
    log_error(log,
              "V1 encrypted password: got %zu fields, expected %d fields",
              count, 
              V1_FIELD_COUNT);
    goto err;
  }

  CALL(parse_field(log, fields[0], field_v, &v));
  if (0 != str_compare(v, str_get("1"))) {
    log_error(log, 
              "V1 encrypted password: got version '"STRFMT"', expected '1'",
              STRVA(v));
    goto err;
  }
  CALL(parse_field_b64_copy(log, fields[1], field_pks, pks));
  CALL(parse_field_b64_copy(log, fields[2], field_piv, piv));
  CALL(parse_field_b64_copy(log, fields[3], field_ps, ps));
  CALL(parse_field_b64(log, fields[4], field_p, &p));
  CALL(parse_field_b64_copy(log, fields[5], field_hsks, hsks));
  CALL(parse_field(log, fields[6], field_hski, &hski));
  hski_value = atol(hski.ptr);
  if (hski_value <= 0) {
    log_error(log,"invalid hski value %ld, must be > 0", hski_value);
    goto err;
  }
  hmac_secret_params->kdp.pbkdf_iterations = hski_value;
  CALL(parse_field_b64_copy(log, fields[7], field_hsiv, hsiv));
  CALL(parse_field_b64_copy(log, fields[8], field_hss, hss));
  CALL(parse_field_b64(log, fields[9], field_hs, &hs));

  *password_ciphertext = p;
  p.ptr = NULL;
  *hmac_secret_ciphertext = hs;
  hs.ptr = NULL;
  result = true;

err:
  free(hs.ptr);
  free(p.ptr);

  return result;
}


/*
 * Public Interface
 */

bool generate_hmac_salt(const log_t *log, unsigned char *hmac_salt)
{
  CALL_OSSL(RAND_bytes(hmac_salt, HMAC_SALT_LENGTH));
  return true;
err:
  return false;
}

bool encrypt_password(
  const log_t *log,
  const char *username,
  const unsigned char *credential_id_ptr,
  size_t credential_id_len,
  const unsigned char *hmac_salt,
  const unsigned char *hmac_secret_ptr,
  size_t hmac_secret_len,
  const char *password,
  char **encrypted_password)
{
  bool result = false;
  bytes_t credential_id = 
    bytes_get((unsigned char *)credential_id_ptr, credential_id_len);
  bytes_t hmac_secret = 
    bytes_get((unsigned char *)hmac_secret_ptr, hmac_secret_len);
  bytes_t password_bytes = 
    bytes_get((unsigned char *)password, strlen(password));
  encrypted_password_params_v1_t epp;
  aes_256_gcm_key_t hskey;
  bytes_t ep = BYTESINIT(NULL, 0);
  encrypted_hmac_secret_params_v1_t ehsp;
  aes_256_gcm_key_t pkey;
  bytes_t ehs = BYTESINIT(NULL, 0);

  // Encrypt the password using the HMAC secret
  CALL(initialize_encrypted_password_params_v1(log, hmac_salt, &epp));
  CALL(derive_key_from_hmac_secret(log, username, credential_id, &epp, 
    hmac_secret, &hskey));
  CALL(encrypt_aes_256_gcm(log, &epp.cp, &hskey, password_bytes, &ep));

  // Encrypt the HMAC secret using the password
  CALL(initialize_encrypted_hmac_secret_params_v1(log, &ehsp));
  CALL(derive_key_from_password(log, &ehsp.kdp, password, &pkey));
  CALL(encrypt_aes_256_gcm(log, &ehsp.cp, &pkey, hmac_secret, &ehs));

  // Serialize all fields
  CALL(serialize_encrypted_password(log, &epp, ep, &ehsp, ehs, 
    encrypted_password));
  result = true;

err:
  free(ehs.ptr);
  free(ep.ptr);
  cleanse_key(&pkey);
  cleanse_key(&hskey);
  return result;
}

bool get_hmac_salt_from_encrypted_password(
  const log_t *log,
  const char *encrypted_password,
  unsigned char *hmac_salt)
{
  bool result = false;
  encrypted_password_params_v1_t epp;
  bytes_t ep = BYTESINIT(NULL, 0);
  encrypted_hmac_secret_params_v1_t ehsp;
  bytes_t ehs = BYTESINIT(NULL, 0);

  // Deserialize all fields
  CALL(deserialize_encrypted_password(log, encrypted_password, &epp, &ep, 
    &ehsp, &ehs));

  memcpy(hmac_salt, epp.kdp.hmac_salt, sizeof(epp.kdp.hmac_salt));
  result = true;
  
err:
  free(ehs.ptr);
  free(ep.ptr);
  return result;
}

bool decrypt_password(
  const log_t *log,
  const char *username,
  const unsigned char *credential_id_ptr,
  size_t credential_id_len,
  const unsigned char *hmac_secret_ptr,
  size_t hmac_secret_len,
  const char *encrypted_password,
  char **password)
{
  bool result = false;
  encrypted_password_params_v1_t epp;
  bytes_t ep = BYTESINIT(NULL, 0);
  encrypted_hmac_secret_params_v1_t ehsp;
  bytes_t ehs = BYTESINIT(NULL, 0);
  bytes_t credential_id = 
    bytes_get((unsigned char *)credential_id_ptr, credential_id_len);
  bytes_t hmac_secret = 
    bytes_get((unsigned char *)hmac_secret_ptr, hmac_secret_len);
  aes_256_gcm_key_t hskey;
  bytes_t p = BYTESINIT(NULL, 0);

  // Deserialize all fields
  CALL(deserialize_encrypted_password(log, encrypted_password, &epp, &ep, 
    &ehsp, &ehs));

  // Decrypt the password using the HMAC secret
  CALL(derive_key_from_hmac_secret(log, username, credential_id, &epp, 
    hmac_secret, &hskey));
  CALL(decrypt_aes_256_gcm(log, &epp.cp, &hskey, ep, &p));

  *password = (char*)p.ptr;
  p.ptr = NULL;
  result = true;

err:
  cleanse_and_free_owned_bytes(&p);
  cleanse_key(&hskey);
  free(ehs.ptr);
  free(ep.ptr);
  return result;
}

bool update_encrypted_password(
  const log_t *log,
  const char *old_password,
  const char *new_password,
  const char *username,
  const unsigned char *credential_id_ptr,
  size_t credential_id_len,
  const char *old_encrypted_password,
  char **new_encrypted_password)
{
  bool result = false;
  encrypted_password_params_v1_t old_epp;
  bytes_t old_ep = BYTESINIT(NULL, 0);
  encrypted_hmac_secret_params_v1_t old_ehsp;
  bytes_t old_ehs = BYTESINIT(NULL, 0);
  aes_256_gcm_key_t old_pkey;
  bytes_t hs = BYTESINIT(NULL, 0);

  if (!old_password) {
    log_error(log, "Old password is required to update the encrypted password");
    goto err;
  }

  // Deserialize all old fields
  CALL(deserialize_encrypted_password(log, old_encrypted_password, 
    &old_epp, &old_ep, &old_ehsp, &old_ehs));

  // Decrypt HMAC secret using old password
  CALL(derive_key_from_password(log, &old_ehsp.kdp, old_password, &old_pkey));
  CALL(decrypt_aes_256_gcm(log, &old_ehsp.cp, &old_pkey, old_ehs, &hs));

  // Re-create the encrypted password. Use new cryptographic parameters.
  CALL(encrypt_password(log, username, credential_id_ptr, credential_id_len,
    hs.ptr, hs.len, new_password, new_encrypted_password));

  result = true;

err:
  cleanse_and_free_owned_bytes(&hs);
  cleanse_key(&old_pkey);
  free(old_ehs.ptr);
  free(old_ep.ptr);
  return result;
}

