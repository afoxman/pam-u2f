/*
 * Copyright (C) 2026 Yubico AB - See COPYING
 */

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "crypto.h"
#include "log.h"

#define assert_ok(expr) assert(0 == (expr))
#define assert_null(expr) assert(NULL == (expr))

static const unsigned char hmac_salt_blank[HMAC_SALT_LENGTH] = {0};

// base64: BefXwk61/nwx5nO0J3buqMib/k1br1wF4mvndbQ7eis=
static const unsigned char hmac_salt[HMAC_SALT_LENGTH] = {
  0x05, 0xe7, 0xd7, 0xc2, 0x4e, 0xb5, 0xfe, 0x7c,
  0x31, 0xe6, 0x73, 0xb4, 0x27, 0x76, 0xee, 0xa8,
  0xc8, 0x9b, 0xfe, 0x4d, 0x5b, 0xaf, 0x5c, 0x05,
  0xe2, 0x6b, 0xe7, 0x75, 0xb4, 0x3b, 0x7a, 0x2b
};

static const unsigned char cred_id_buffer[10] = {
  0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 
  0x99, 0xAA
};
static const bytes_t cred_id = BYTESINIT(
  (unsigned char*)cred_id_buffer, sizeof(cred_id_buffer));

// string: "It's a secret to everyone, Link."
// base64: SXQncyBhIHNlY3JldCB0byBldmVyeW9uZSwgTGluay4K
static const unsigned char hmac_secret_buffer[32] = {
  0x49, 0x74, 0x27, 0x73, 0x20, 0x61, 0x20, 0x73,
  0x65, 0x63, 0x72, 0x65, 0x74, 0x20, 0x74, 0x6f,
  0x20, 0x65, 0x76, 0x65, 0x72, 0x79, 0x6f, 0x6e,
  0x65, 0x2c, 0x20, 0x4c, 0x69, 0x6e, 0x6b, 0x2e
};
static const bytes_t hmac_secret = BYTESINIT(
  (unsigned char*)hmac_secret_buffer, sizeof(hmac_secret_buffer));


#define USERNAME      "gjanek"
#define PASSWORD      "Setec Astronomy"
#define NEW_PASSWORD  "Too many secrets"


static log_t *open_log(log_level_t min, const char *caller, FILE *file) {
  log_t *log = log_create_file(min, caller, file);
  assert(NULL != log);
  log_info(log, "Running");
  return log;
}

static bool run_encrypt_password(const char *caller, const char *user,
                                 const char *password) {
  log_t *log = open_log(log_level_trace, caller, stdout);

  char *ep = NULL;
  bool result = encrypt_password(log, user, cred_id, hmac_salt, hmac_secret,
    password, &ep);
  if (result) {
    assert(NULL != ep);
    assert(strlen(ep) > 0);
  } else {
    assert(NULL == ep);
  }

  free(ep);
  log_free(log);

  return result;
}

static bool run_decrypt_password(const char *caller, const char *decrypt_user, 
  bytes_t decrypt_cred_id, bytes_t decrypt_hmac_secret) 
{
  log_t *log = open_log(log_level_trace, caller, stdout);
  char *ep = NULL;
  assert(encrypt_password(log, USERNAME, cred_id, hmac_salt, hmac_secret,
    PASSWORD, &ep));
  assert(NULL != ep);
  assert(strlen(ep) > 0);

  char *p = NULL;
  bool result = decrypt_password(log, decrypt_user, decrypt_cred_id, 
    decrypt_hmac_secret, ep, &p);
  if (result) {
    assert(NULL != p);
    assert(0 == strcmp(p, PASSWORD));
  } else {
    assert(NULL == p);
  }

  free(p);
  free(ep);
  log_free(log);

  return result;
}

static bool run_update_encrypted_password(const char *caller, 
  const char *initial_password, const char *old_password, 
  const char *new_password, const char *new_user, bytes_t new_cred_id) 
{
  log_t *log = open_log(log_level_trace, caller, stdout);

  char *ep = NULL;
  assert(encrypt_password(log, USERNAME, cred_id, hmac_salt, hmac_secret,
    initial_password, &ep));
  assert(NULL != ep);
  assert(strlen(ep) > 0);

  char *new_ep = NULL;
  bool result = update_encrypted_password(log, old_password, new_password, 
    new_user, new_cred_id, ep, &new_ep);
  if (result) {
    assert(NULL != new_ep);
    assert(strlen(new_ep) > 0);
    assert(0 != strcmp(ep, new_ep));

    char *p = NULL;
    assert(decrypt_password(log, new_user, new_cred_id, hmac_secret, new_ep, 
      &p));
    assert(NULL != p);
    assert(0 == strcmp(p, new_password ? new_password : ""));
    free(p);
  }

  free(new_ep);
  free(ep);
  log_free(log);

  return result;
}

/*
 * Test Cases 
 */

static void test_generate_hmac_salt_succeeds(void) {
  log_t *log = open_log(log_level_trace, __func__, stdout);
  unsigned char hs[HMAC_SALT_LENGTH] = {0};
  assert(generate_hmac_salt(log, hs));
  assert(0 != memcmp(hs, hmac_salt_blank, HMAC_SALT_LENGTH));
  log_free(log);
}

static void test_encrypt_password_succeeds(void) {
  assert(run_encrypt_password(__func__, USERNAME, PASSWORD));
}

static void test_encrypt_password_succeeds_empty_user(void) {
  assert(run_encrypt_password(__func__, "", PASSWORD));
}

static void test_encrypt_password_succeeds_NULL_password(void) {
  assert(run_encrypt_password(__func__, USERNAME, NULL));
}

static void test_encrypt_password_succeeds_empty_password(void) {
  assert(run_encrypt_password(__func__, USERNAME, ""));
}

static void test_get_hmac_salt_from_encrypted_password_fails_invalid_ep(void) {
  log_t *log = open_log(log_level_trace, __func__, stdout);
  unsigned char hs[HMAC_SALT_LENGTH] = {0};
  assert(!get_hmac_salt_from_encrypted_password(log, "invalid", hs));
  log_free(log);
}

static void test_get_hmac_salt_from_encrypted_password_succeeds(void) {
  log_t *log = open_log(log_level_trace, __func__, stdout);
  const char *ep = "v=1|"
                   "hs=BefXwk61/nwx5nO0J3buqMib/k1br1wF4mvndbQ7eis=|"
                   "hi=LvlWo2UiQqpAX6OF|"
                   "ht=KIuL3y7s1L5uSr3F3VLqHA==|"
                   "ep=K52KqkVHZrpCpGI=|"
                   "ps=phtwO89bjrsgIcqBsvt5oTDckaQgQ/awICChzPCP6+w=|"
                   "pc=1000000|"
                   "pi=LvlWo2UiQqpAX6OF|"
                   "pt=KIuL3y7s1L5uSr3F3VLqHA==|"
                   "eh=phtwO89bjrsgIcqBsvt5oTDckaQgQ/awICChzPCP6+w=";
  unsigned char hs[HMAC_SALT_LENGTH] = {0};
  assert(get_hmac_salt_from_encrypted_password(log, ep, hs));
  assert(0 == memcmp(hs, hmac_salt, HMAC_SALT_LENGTH));
  log_free(log);
}

static void test_decrypt_password_succeeds(void) {
  assert(run_decrypt_password(__func__, USERNAME, cred_id, hmac_secret));
}

static void test_decrypt_password_fails_when_user_changes(void) {
  assert(!run_decrypt_password(__func__, "different-user", cred_id, 
    hmac_secret));
}

static void test_decrypt_password_fails_when_cred_id_changes(void) {
  unsigned char new_cred_id_buffer[10] = {
    0x33, 0x22, 0x11, 0x66, 0x55, 0x44, 0x99, 0x88, 
    0x77, 0xCC
  };
  bytes_t new_cred_id = BYTESINIT((unsigned char*)new_cred_id_buffer, 
    sizeof(new_cred_id_buffer));
  assert(!run_decrypt_password(__func__, USERNAME, new_cred_id, hmac_secret));
}

static void test_decrypt_password_fails_when_hmac_secret_changes(void) {
  unsigned char new_hmac_secret_buffer[32] = {
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77
  };
  bytes_t new_hmac_secret = BYTESINIT(
    (unsigned char*)new_hmac_secret_buffer, sizeof(new_hmac_secret_buffer));
  assert(!run_decrypt_password(__func__, USERNAME, cred_id, new_hmac_secret));
}

static void test_decrypt_password_fails_NULL_ep(void) {
  log_t *log = open_log(log_level_trace, __func__, stdout);
  const char *ep = NULL;
  char *p = NULL;
  assert(!decrypt_password(log, USERNAME, cred_id, hmac_secret, ep, &p));
  log_free(log);
}

static void test_decrypt_password_fails_empty_ep(void) {
  log_t *log = open_log(log_level_trace, __func__, stdout);
  const char *ep = "";
  char *p = NULL;
  assert(!decrypt_password(log, USERNAME, cred_id, hmac_secret, ep, &p));
  log_free(log);
}

static void test_decrypt_password_fails_invalid_ep(void) {
  log_t *log = open_log(log_level_trace, __func__, stdout);
  const char *ep = "invalid";
  char *p = NULL;
  assert(!decrypt_password(log, USERNAME, cred_id, hmac_secret, ep, &p));
  log_free(log);
}

static void test_update_encrypted_password_succeeds(void) {
  char *old = PASSWORD;
  char *new = NEW_PASSWORD;
  assert(run_update_encrypted_password(__func__, old, old, new, USERNAME, 
    cred_id));
}

static void test_update_encrypted_password_succeeds_empty_old_password(void) {
  char *old = "";
  char *new = NEW_PASSWORD;
  assert(run_update_encrypted_password(__func__, old, old, new, USERNAME, 
    cred_id));
}

static void test_update_encrypted_password_succeeds_NULL_new_password(void) {
  char *old = PASSWORD;
  char *new = NULL;
  assert(run_update_encrypted_password(__func__, old, old, new, USERNAME, 
    cred_id));
}

static void test_update_encrypted_password_succeeds_empty_new_password(void) {
  char *old = PASSWORD;
  char *new = "";
  assert(run_update_encrypted_password(__func__, old, old, new, USERNAME,
    cred_id));
}

static void test_update_encrypted_password_fails_without_old_password(void) {
  assert(!run_update_encrypted_password(__func__, PASSWORD, NULL,
    NEW_PASSWORD, USERNAME, cred_id));
}

static void test_update_encrypted_password_fails_when_old_password_is_wrong(void) {
  assert(!run_update_encrypted_password(__func__, PASSWORD, "wrong-password",
    NEW_PASSWORD, USERNAME, cred_id));
}

static void test_update_encrypted_password_fails_when_user_is_wrong(void) {
  assert(!run_update_encrypted_password(__func__, PASSWORD, PASSWORD,
    NEW_PASSWORD, "wrong-user", cred_id));
}

static void test_update_encrypted_password_fails_when_cred_id_is_wrong(void) {
  unsigned char new_cred_id_buffer[10] = {
    0x33, 0x22, 0x11, 0x66, 0x55, 0x44, 0x99, 0x88, 
    0x77, 0xCC
  };
  bytes_t new_cred_id = BYTESINIT((unsigned char*)new_cred_id_buffer, 
    sizeof(new_cred_id_buffer));
  assert(!run_update_encrypted_password(__func__, PASSWORD, PASSWORD,
    NEW_PASSWORD, USERNAME, new_cred_id));
}

int main(void) {
  test_generate_hmac_salt_succeeds();

  test_encrypt_password_succeeds();
  test_encrypt_password_succeeds_empty_user();
  test_encrypt_password_succeeds_NULL_password();
  test_encrypt_password_succeeds_empty_password();

  test_get_hmac_salt_from_encrypted_password_fails_invalid_ep();
  test_get_hmac_salt_from_encrypted_password_succeeds();

  test_decrypt_password_succeeds();
  test_decrypt_password_fails_when_user_changes();
  test_decrypt_password_fails_when_cred_id_changes();
  test_decrypt_password_fails_when_hmac_secret_changes();
  test_decrypt_password_fails_NULL_ep();
  test_decrypt_password_fails_empty_ep();
  test_decrypt_password_fails_invalid_ep();

  test_update_encrypted_password_succeeds();
  test_update_encrypted_password_succeeds_empty_old_password();
  test_update_encrypted_password_succeeds_NULL_new_password();
  test_update_encrypted_password_succeeds_empty_new_password();
  test_update_encrypted_password_fails_without_old_password();
  test_update_encrypted_password_fails_when_old_password_is_wrong();
  test_update_encrypted_password_fails_when_user_is_wrong();
  test_update_encrypted_password_fails_when_cred_id_is_wrong();

  return 0;
}
