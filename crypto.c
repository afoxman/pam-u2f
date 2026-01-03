/*
 * Copyright (C) 2026 Yubico AB - See COPYING
 */

/* 
 * Cryptographic Algorithms for Secure Password Storage and Update
 * Using a FIDO2 Authenticator
 *
 * === Summary ===
 * 
 * The purpose of this library is to assist with "logging a user in" via their
 * FIDO2 authenticator (e.g. Yubikey V5+, Yubikey Bio).
 * 
 * To log in, a user's password must be provided to the operating system via 
 * the PAM authentication stack. Existing PAM modules, like the GNOME keyring,
 * use the password to unlock the user's secret store automatically.
 * 
 * A user's password is not stored in a typical configuration, so this system
 * must store it. Further, the password must be encrypted and bound to a
 * specific FIDO2 authenticator, to ensure it cannot be used by anyone other
 * than the owning user. This is done using the FIDO2 hmac-secret extension.
 * 
 * This system must react to password changes for the user, updating the
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
 * We provide the authenticator with a credential id and a salt (both randomly 
 * generated). The authenticator combines these with its own secret key, which
 * never leaves the device. It then emits the bound secret.
 * 
 * The secret is used to derive a 256-bit symmetric key, which encrypts the
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
 *   - User name
 *   - Credential ID
 *   - Salt used when deriving a key from the HMAC secret
 *   - Encryption key initialization vector
 *   - 0x01 0x00
 *       Length of a V1 derived key, which is 256 bits.
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
 * Parameters such as salt and initialization vector are used to increase 
 * complexity, making compromise unlikely. Storing them in the clear gives no
 * advantage to an attacker.
 * 
 * === Password Updates ===
 * 
 * When a password change occurs for a user, the new password must be
 * encrypted and updated in the system to keep the "login" flow operational.
 * To do this, the HMAC secret is needed, yet it is only accessible via the
 * FIDO2 authenticator. So the HMAC secret itself must be encrypted and 
 * stored, alongside the password.
 * 
 * The user's password is used to derive a 256-bit symmetric key with a 
 * NIST-compliant algorithm for password-based key derivation:
 * 
 * https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-132.pdf
 *
 * The derived key is used to encrypt and decrypt the HMAC secret. The
 * encrypted HMAC secret and associated parameters are stored next to the
 * encrypted password. All of this data is safe to store in the clear.
 * 
 * When deriving the key, the user's name and credential id are incorporated,
 * binding the encrypted HMAC secret to the existing chain of trust, rooted
 * in the originating FIDO2 authenticator.
 * 
 * When the password change occurs, PAM delivers both the current and new 
 * passwords to all modules. This system uses the current password to decrypt
 * the HMAC secret, and the new password to (re)encrypt it. This is a 
 * well-known process, and is how the GNOME keyring (among others) handles
 * password changes.
 * 
 * NOTE: When the superuser resets a password, only the new password is
 *       provided. This means the HMAC secret cannot be decrypted, and the
 *       encrypted password cannot be updated.
 *
 *       While this breaks the "login" flow, it is a well-known drawback
 *       of the default password architecture in Unix systems. It impacts all
 *       PAM-based modules. For example, the GNOME keyring loses automatic
 *       unlock on login, and requires user intervention to be repaired. If
 *       the user does not have the old password, the keyring is lost. Users
 *       in this situation must re-enroll using their FIDO2 authenticator.
 */

#include <openssl/core.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/rand.h>
#include <openssl/types.h>

#include <stdio.h>
#include <string.h>

#include "b64.h"
#include "crypto.h"
#include "util.h"

#define V1_DOMAIN_STR                "u2f-local-authentication-v1"
#define V1_DOMAIN_LEN                (sizeof(V1_DOMAIN_STR) - 1)

#define AES_256_GCM_IV_LENGTH        12
#define AES_256_GCM_TAG_LENGTH       16
#define AES_256_GCM_KEY_LENGTH       32
#define AES_256_GCM_KEY_LENGTH_BITS  (AES_256_GCM_KEY_LENGTH * 8)

#define PASSWORD_KEY_V1_ITERATIONS   (1 * 1000 * 1000)

#define B64_CHARLEN_FROM_BYTELEN(x)  ((((x + 2) / 3) * 4) + 1)

// HMAC secret parameters for encrypting a password
typedef struct {
  unsigned char hmac_salt[HMAC_SALT_LENGTH];
  unsigned char aes_iv[AES_256_GCM_IV_LENGTH];
  unsigned char aes_tag[AES_256_GCM_TAG_LENGTH];
} hparams_v1_t;

// Password parameters for encrypting an HMAC secret
typedef struct {
  unsigned char pbkdf_salt[32];
  size_t pbkdf_iter;
  unsigned char aes_iv[AES_256_GCM_IV_LENGTH];
  unsigned char aes_tag[AES_256_GCM_TAG_LENGTH];
} pparams_v1_t;

typedef struct{
  unsigned char data[AES_256_GCM_KEY_LENGTH];
} aes_256_gcm_key_t;

/*
 * Invocation and Error Handling
 */

#define CALL(f) \
  do { \
    if (!(f)) { \
      goto err; \
    } \
  } while (0)

#define CALL_OSSL(f) \
  do { \
    if ((long)(f) < 1) { \
      log_ossl_error(log, #f); \
      goto err; \
    } \
  } while (0)

static void log_ossl_error(const log_t *log, const char *api) {
  if (0 != ERR_peek_last_error()) {
    char err[512];
    ERR_error_string_n(ERR_peek_last_error(), err, sizeof(err));
    log_error(log, "%s failed: %s", api, err);
  } else {
    log_error(log, "%s failed", api);
  }
}

/*
 * Object Management
 */

static bool init_hparams_v1(const log_t *log, const unsigned char *hmac_salt,
                            hparams_v1_t *hparams) {
  memcpy(hparams->hmac_salt, hmac_salt, sizeof(hparams->hmac_salt));
  CALL_OSSL(RAND_bytes(hparams->aes_iv, sizeof(hparams->aes_iv)));
  memset(hparams->aes_tag, 0, sizeof(hparams->aes_tag));
  return true;
err:
  return false;
}

static bool init_pparams_v1(const log_t *log, pparams_v1_t *pparams) {
  CALL_OSSL(RAND_bytes(pparams->pbkdf_salt, sizeof(pparams->pbkdf_salt)));
  pparams->pbkdf_iter = PASSWORD_KEY_V1_ITERATIONS;
  CALL_OSSL(RAND_bytes(pparams->aes_iv, sizeof(pparams->aes_iv)));
  memset(pparams->aes_tag, 0, sizeof(pparams->aes_tag));
  return true;
err:
  return false;
}

static void cleanse_key(aes_256_gcm_key_t *key) {
  OPENSSL_cleanse(key->data, sizeof(key->data));
}

static void cleanse_and_free_owned_bytes(bytes_t b) {
  if (b.ptr) {
    OPENSSL_cleanse(b.ptr, b.len);
    free(b.ptr);
  }
}


/*
 * Key Derivation
 */

static bytes_t bytes_copy(bytes_t buffer, const void *ptr, size_t len) {
  if (buffer.len > 0 && len > 0) {
    if (len > buffer.len)
      len = buffer.len;

    memcpy(buffer.ptr, ptr, len);
    buffer.ptr += len;
    buffer.len -= len;
  }
  return buffer;
}

static bool derive_key_from_hmac_secret(const log_t *log, const char *username,
  bytes_t credential_id, const hparams_v1_t *hparams, bytes_t hmac_secret, 
  aes_256_gcm_key_t *key) 
{
  bool result = false;
  unsigned char info_buffer[1024];
  bytes_t info = BYTESINIT(info_buffer, sizeof(info_buffer));
  const size_t aes_256_key_length = AES_256_GCM_KEY_LENGTH_BITS;
  int kdf_mode = EVP_KDF_HKDF_MODE_EXTRACT_AND_EXPAND;
  OSSL_PARAM oparams[6];
  size_t n = 0;
  EVP_KDF *kdf = NULL;
  EVP_KDF_CTX *ctx = NULL;

  info = bytes_copy(info, V1_DOMAIN_STR, V1_DOMAIN_LEN);
  info = bytes_copy(info, username, strlen(username));
  info = bytes_copy(info, credential_id.ptr, credential_id.len);
  info = bytes_copy(info, hparams->hmac_salt, sizeof(hparams->hmac_salt));
  info = bytes_copy(info, hparams->aes_iv, sizeof(hparams->aes_iv));
  info = bytes_copy(info, &aes_256_key_length, sizeof(aes_256_key_length));
  info.len = info.ptr - info_buffer;
  info.ptr = info_buffer;

  // OpenSSL docs: https://docs.openssl.org/3.0/man7/EVP_KDF-HKDF
  oparams[n++] = OSSL_PARAM_construct_int(OSSL_KDF_PARAM_MODE, &kdf_mode);
  oparams[n++] = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST,
    SN_sha256, strlen(SN_sha256));
  oparams[n++] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT,
    (void *)hparams->hmac_salt, sizeof(hparams->hmac_salt));
  oparams[n++] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY,
    hmac_secret.ptr, hmac_secret.len);
  oparams[n++] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO,
    info.ptr, info.len);
  oparams[n++] = OSSL_PARAM_construct_end();
  if (n > sizeof(oparams) / sizeof(oparams[0])) {
    log_error(log, "oparams overflow: n=%zu", n);
    goto err;
  }

  CALL_OSSL(kdf = EVP_KDF_fetch(NULL, "HKDF", NULL));
  CALL_OSSL(ctx = EVP_KDF_CTX_new(kdf));
  CALL_OSSL(EVP_KDF_derive(ctx, key->data, sizeof(key->data), oparams));
  result = true;

err:
  EVP_KDF_CTX_free(ctx);
  EVP_KDF_free(kdf);
  return result;
}

static bool derive_key_from_password(const log_t *log, const char *username,
  bytes_t cred_id, const pparams_v1_t *pparams, const char *password, 
  aes_256_gcm_key_t *key)
{
  bool result = false;
  unsigned char info_buffer[1024];
  bytes_t info = BYTESINIT(info_buffer, sizeof(info_buffer));
  unsigned char salt[32];
  unsigned int salt_len = 0;
  EVP_MD *md = NULL;
  OSSL_PARAM oparams[5];
  size_t n = 0;
  EVP_KDF *kdf = NULL;
  EVP_KDF_CTX *ctx = NULL;

  // Bind the PBKDF2 salt, username, and credential together.
  info = bytes_copy(info, pparams->pbkdf_salt, sizeof(pparams->pbkdf_salt));
  info = bytes_copy(info, username, strlen(username));
  info = bytes_copy(info, cred_id.ptr, cred_id.len);
  info.len = info.ptr - info_buffer;
  info.ptr = info_buffer;
  CALL_OSSL(md = EVP_MD_fetch(NULL, "SHA256", NULL));
  CALL_OSSL(EVP_Digest(info.ptr, info.len, salt, &salt_len, md, NULL));
  if (sizeof(salt) != salt_len) {
    log_error(log, "sha256 failure -- expected %zu bytes, got %u bytes",
              sizeof(salt), salt_len);
    goto err;
  }

  // OpenSSL docs: https://docs.openssl.org/3.0/man7/EVP_KDF-PBKDF2
  oparams[n++] = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, 
    SN_sha256, strlen(SN_sha256));
  oparams[n++] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT,
    (void *)salt, salt_len);
  oparams[n++] = OSSL_PARAM_construct_size_t(OSSL_KDF_PARAM_ITER,
    (size_t *)&pparams->pbkdf_iter);
  oparams[n++] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_PASSWORD,
    (void *)password, password ? strlen(password) : 0);
  oparams[n++] = OSSL_PARAM_construct_end();
  if (n > sizeof(oparams) / sizeof(oparams[0])) {
    log_error(log, "oparams overflow: n=%zu", n);
    goto err;
  }

  CALL_OSSL(kdf = EVP_KDF_fetch(NULL, "PBKDF2", NULL));
  CALL_OSSL(ctx = EVP_KDF_CTX_new(kdf));
  CALL_OSSL(EVP_KDF_derive(ctx, key->data, sizeof(key->data), oparams));
  result = true;

err:
  EVP_KDF_CTX_free(ctx);
  EVP_KDF_free(kdf);
  EVP_MD_free(md);
  return result;
}

/*
 * Encryption
 */

static bool encrypt_aes_256_gcm(const log_t *log, const aes_256_gcm_key_t *key,
  const unsigned char *iv, bytes_t plaintext, bytes_t *ciphertext, 
  unsigned char *tag)
{
  bool result = false;
  EVP_CIPHER_CTX *ctx = NULL;
  int n;
  int length;

  if (!(ciphertext->ptr = malloc(plaintext.len))) {
    log_error(log, "failed to allocate %zu bytes", plaintext.len);
    goto err;
  }
  ciphertext->len = plaintext.len;

  CALL_OSSL(ctx = EVP_CIPHER_CTX_new());
  CALL_OSSL(EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL));
  CALL_OSSL(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN,
    AES_256_GCM_IV_LENGTH, NULL));
  CALL_OSSL(EVP_EncryptInit_ex(ctx, NULL, NULL, key->data, iv));
  CALL_OSSL(EVP_EncryptUpdate(ctx, ciphertext->ptr, &n, 
    plaintext.ptr, (int)plaintext.len));
  length = n;
  if ((size_t)length > ciphertext->len) {
    log_error(log, "encryption buffer overflow (update): length=%d", length);
    goto err;
  }
  CALL_OSSL(EVP_EncryptFinal_ex(ctx, ciphertext->ptr + length, &n));
  length += n;
  if ((size_t)length > ciphertext->len) {
    log_error(log, "encryption buffer overflow (final): length=%d", length);
    goto err;
  }
  CALL_OSSL(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG,
    AES_256_GCM_TAG_LENGTH, tag));
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

static bool decrypt_aes_256_gcm(const log_t *log, const aes_256_gcm_key_t *key,
  const unsigned char *iv, bytes_t ciphertext, const unsigned char *tag,
  bytes_t *plaintext)
{
  bool result = false;
  bytes_t out = BYTESINIT(NULL, 0);
  EVP_CIPHER_CTX *ctx = NULL;
  int n;
  int length;

  if (!(out.ptr = malloc(ciphertext.len + 1))) {
    log_error(log, "failed to allocate %zu bytes", ciphertext.len + 1);
    goto err;
  }
  out.len = ciphertext.len + 1;

  CALL_OSSL(ctx = EVP_CIPHER_CTX_new());
  CALL_OSSL(EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL));
  CALL_OSSL(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 
    AES_256_GCM_IV_LENGTH, NULL));
  CALL_OSSL(EVP_DecryptInit_ex(ctx, NULL, NULL, key->data, iv));
  CALL_OSSL(EVP_DecryptUpdate(ctx, out.ptr, &n, ciphertext.ptr, 
    (int)ciphertext.len));
  length = n;
  if ((size_t)length + 1 > out.len) {
    log_error(log, "decryption buffer overflow (update): length=%d", length);
    goto err;
  }
  CALL_OSSL(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 
    AES_256_GCM_TAG_LENGTH, (void*)tag));
  CALL_OSSL(EVP_DecryptFinal_ex(ctx, out.ptr + length, &n));
  length += n;
  if ((size_t)length + 1 > out.len) {
    log_error(log, "decryption buffer overflow (final): length=%d", length);
    goto err;
  }
  out.ptr[length] = '\0';
  out.len = length;

  *plaintext = out;
  out.ptr = NULL;
  result = true;

err:
  EVP_CIPHER_CTX_free(ctx);
  cleanse_and_free_owned_bytes(out);
  return result;
}

/*
 * Serialization
 */

static size_t split(char *s, const char *delim, char **tokens, size_t len) {
  size_t count = 0;
  char *saveptr;
  char *token = strtok_r(s, delim, &saveptr);
  while (token && count < len) {
    tokens[count++] = token;
    token = strtok_r(NULL, delim, &saveptr);
  }
  return count;
}

static bool read_size_t(const log_t *log, const char *s,
                        const char *prefix, size_t* out) {
  size_t prefix_len = strlen(prefix);
  if (0 != strncmp(s, prefix, prefix_len)) {
    log_error(log, "field is missing prefix %s: %s", prefix, s);
    goto err;
  }
  long l = strtoul(s + prefix_len, NULL, 10);
  if (LONG_MIN == l || LONG_MAX == l || l < 0) {
    log_error(log, "field value is out of range (long): %s", s);
    goto err;
  }
  *out = (size_t)l;
  return true;

err:
  return false;
}

static bool read_b64_bytes(const log_t *log, const char *s,
                           const char *prefix, bytes_t *out) {
  size_t prefix_len = strlen(prefix);
  if (0 != strncmp(s, prefix, prefix_len)) {
    log_error(log, "field is missing prefix %s: %s", prefix, s);
    goto err;
  }
  CALL_OSSL(b64_decode(s + prefix_len, (void**)&out->ptr, &out->len));
  return true;

err:
  return false;
}

static bool read_b64(const log_t *log, char *s, const char *prefix,
                     unsigned char *ptr, size_t len) {
  bool result = false;
  bytes_t b;
  CALL(read_b64_bytes(log, s, prefix, &b));
  if (b.len != len) {
    log_error(log, "field size is wrong: got %zu bytes, expected %zu bytes",
              b.len, len);
    goto err;
  }
  memcpy(ptr, b.ptr, len);
  result = true;

err:
  free(b.ptr);
  return result;
}

static bool serialize(const log_t *log, const hparams_v1_t *hparams,
  bytes_t pciphertext, const pparams_v1_t *pparams, bytes_t hciphertext,
  char **s) 
{
  bool result = false;
  char *hs = NULL;
  char *hi = NULL;
  char *ht = NULL;
  char *ep = NULL;
  char *ps = NULL;
  char *pi = NULL;
  char *pt = NULL;
  char *eh = NULL;

  CALL_OSSL(b64_encode(hparams->hmac_salt, sizeof(hparams->hmac_salt), &hs));
  CALL_OSSL(b64_encode(hparams->aes_iv, sizeof(hparams->aes_iv), &hi));
  CALL_OSSL(b64_encode(hparams->aes_tag, sizeof(hparams->aes_tag), &ht));
  if (pciphertext.len > 0)
    CALL_OSSL(b64_encode(pciphertext.ptr, pciphertext.len, &ep));
  CALL_OSSL(b64_encode(pparams->pbkdf_salt, sizeof(pparams->pbkdf_salt), &ps));
  CALL_OSSL(b64_encode(pparams->aes_iv, sizeof(pparams->aes_iv), &pi));
  CALL_OSSL(b64_encode(pparams->aes_tag, sizeof(pparams->aes_tag), &pt));
  CALL_OSSL(b64_encode(hciphertext.ptr, hciphertext.len, &eh));

  if (-1 == asprintf(s,
      "v=1|hs=%s|hi=%s|ht=%s|ep=%s|ps=%s|pc=%zu|pi=%s|pt=%s|eh=%s",
      hs, hi, ht, ep ? ep : "", ps, pparams->pbkdf_iter, pi, pt, eh))
  {
    log_error(log, "failed to build encrypted password string: %s (%d)",
              strerror(errno), errno);
    goto err;
  }
  result = true;

err:
  free(eh);
  free(pt);
  free(pi);
  free(ps);
  free(ep);
  free(ht);
  free(hi);
  free(hs);

  return result;
}

static bool deserialize(const log_t *log, const char *s, hparams_v1_t *hparams,
  bytes_t *pciphertext, pparams_v1_t *pparams, bytes_t *hciphertext) 
{
  bool result = false;
  char *buffer = NULL;
  char *t[10] = {0};
  size_t count;

  if (!(buffer = strdup(s ? s : ""))) {
    log_error(log, "failed to duplicate encrypted password");
    goto err;
  }
  count = split(buffer, "|", t, 10);
  if (10 != count) {
    log_error(log, "encrypted password: got %zu field(s), expected %d fields",
              count, 9);
    goto err;
  }

  if (0 != strcmp(t[0], "v=1")) {
    log_error(log, "encrypted password: expected v=1, got %s", t[0]);
    goto err;
  }
  CALL(read_b64(log, t[1], "hs=", hparams->hmac_salt,
    sizeof(hparams->hmac_salt)));
  CALL(read_b64(log, t[2], "hi=", hparams->aes_iv, sizeof(hparams->aes_iv)));
  CALL(read_b64(log, t[3], "ht=", hparams->aes_tag, sizeof(hparams->aes_tag)));
  CALL(read_b64_bytes(log, t[4], "ep=", pciphertext));
  CALL(read_b64(log, t[5], "ps=", pparams->pbkdf_salt, 
    sizeof(pparams->pbkdf_salt)));
  CALL(read_size_t(log, t[6], "pc=", &pparams->pbkdf_iter));
  CALL(read_b64(log, t[7], "pi=", pparams->aes_iv, sizeof(pparams->aes_iv)));
  CALL(read_b64(log, t[8], "pt=", pparams->aes_tag, sizeof(pparams->aes_tag)));
  CALL(read_b64_bytes(log, t[9], "eh=", hciphertext));
  result = true;

err:
  free(buffer);
  return result;
}

/*
 * Public Interface
 */

bool generate_hmac_salt(const log_t *log, unsigned char *hmac_salt) {
  CALL_OSSL(RAND_bytes(hmac_salt, HMAC_SALT_LENGTH));
  return true;
err:
  return false;
}

bool encrypt_password(const log_t *log, const char *username,
  bytes_t cred_id, const unsigned char *hmac_salt, bytes_t hmac_secret,
  const char *password, char **encrypted_password)
{
  bool result = false;
  bytes_t pplaintext = BYTESINIT((void*)password, 
    password ? strlen(password) : 0);
  hparams_v1_t hparams;
  aes_256_gcm_key_t hkey;
  bytes_t pciphertext = BYTESINIT(NULL, 0);
  pparams_v1_t pparams;
  aes_256_gcm_key_t pkey;
  bytes_t hciphertext = BYTESINIT(NULL, 0);

  // Encrypt the password using the HMAC secret
  CALL(init_hparams_v1(log, hmac_salt, &hparams));
  CALL(derive_key_from_hmac_secret(log, username, cred_id, &hparams,
    hmac_secret, &hkey));
  CALL(encrypt_aes_256_gcm(log, &hkey, hparams.aes_iv, pplaintext,
    &pciphertext, hparams.aes_tag));

  // Encrypt the HMAC secret using the password
  CALL(init_pparams_v1(log, &pparams));
  CALL(derive_key_from_password(log, username, cred_id, &pparams, password,
    &pkey));
  CALL(encrypt_aes_256_gcm(log, &pkey, pparams.aes_iv, hmac_secret,
    &hciphertext, pparams.aes_tag));

  CALL(serialize(log, &hparams, pciphertext, &pparams, hciphertext,
    encrypted_password));
  result = true;

err:
  free(hciphertext.ptr);
  free(pciphertext.ptr);
  cleanse_key(&pkey);
  cleanse_key(&hkey);
  return result;
}

bool get_hmac_salt_from_encrypted_password(const log_t *log,
  const char *encrypted_password, unsigned char *hmac_salt)
{
  bool result = false;
  hparams_v1_t hparams;
  bytes_t pciphertext = BYTESINIT(NULL, 0);
  pparams_v1_t pparams;
  bytes_t hciphertext = BYTESINIT(NULL, 0);

  // Deserialize all fields
  CALL(deserialize(log, encrypted_password, &hparams, &pciphertext, &pparams,
    &hciphertext));

  memcpy(hmac_salt, hparams.hmac_salt, HMAC_SALT_LENGTH);
  result = true;
  
err:
  free(hciphertext.ptr);
  free(pciphertext.ptr);
  return result;
}

bool decrypt_password(const log_t *log, const char *username, bytes_t cred_id,
  bytes_t hmac_secret, const char *encrypted_password, char **password)
{
  bool result = false;
  hparams_v1_t hparams;
  bytes_t pciphertext = BYTESINIT(NULL, 0);
  pparams_v1_t pparams;
  bytes_t hciphertext = BYTESINIT(NULL, 0);
  aes_256_gcm_key_t hkey;
  bytes_t pplaintext = BYTESINIT(NULL, 0);

  // Deserialize all fields
  CALL(deserialize(log, encrypted_password, &hparams, &pciphertext, &pparams,
    &hciphertext));

  // Decrypt the password using the HMAC secret
  CALL(derive_key_from_hmac_secret(log, username, cred_id, &hparams,
    hmac_secret, &hkey));
  CALL(decrypt_aes_256_gcm(log, &hkey, hparams.aes_iv, pciphertext, 
    hparams.aes_tag, &pplaintext));

  *password = (char*)pplaintext.ptr;
  pplaintext.ptr = NULL;
  result = true;

err:
  cleanse_and_free_owned_bytes(pplaintext);
  cleanse_key(&hkey);
  free(hciphertext.ptr);
  free(pciphertext.ptr);
  return result;
}

bool update_encrypted_password(const log_t *log, const char *old_password,
  const char *new_password, const char *username, bytes_t cred_id,
  const char *old_encrypted_password, char **new_encrypted_password)
{
  bool result = false;
  hparams_v1_t hparams;
  bytes_t pciphertext = BYTESINIT(NULL, 0);
  pparams_v1_t pparams;
  bytes_t hciphertext = BYTESINIT(NULL, 0);
  aes_256_gcm_key_t pkey;
  bytes_t hplaintext = BYTESINIT(NULL, 0);
  unsigned char new_hmac_salt[HMAC_SALT_LENGTH];

  // Deserialize all old fields
  CALL(deserialize(log, old_encrypted_password, &hparams, &pciphertext, 
    &pparams, &hciphertext));

  // Decrypt HMAC secret using old password
  CALL(derive_key_from_password(log, username, cred_id, &pparams, old_password,
    &pkey));
  CALL(decrypt_aes_256_gcm(log, &pkey, pparams.aes_iv, hciphertext,
    pparams.aes_tag, &hplaintext));

  // Re-create the encrypted password. Use new cryptographic parameters.
  CALL_OSSL(RAND_bytes(new_hmac_salt, sizeof(new_hmac_salt)));
  CALL(encrypt_password(log, username, cred_id, new_hmac_salt, hplaintext, 
    new_password, new_encrypted_password));

  result = true;

err:
  cleanse_and_free_owned_bytes(hplaintext);
  cleanse_key(&pkey);
  free(hciphertext.ptr);
  free(pciphertext.ptr);
  return result;
}
