/*
 * Copyright (C) 2026 Yubico AB - See COPYING
 */

#include <assert.h>
#include <pwd.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#include "cfg.h"
#include "crypto.h"
#include "log.h"
#include "util.h"

#define assert_ok(expr) assert(0 == (expr))
#define assert_null(expr) assert(NULL == (expr))

// base64: BefXwk61/nwx5nO0J3buqMib/k1br1wF4mvndbQ7eis=
static const unsigned char hmac_salt[HMAC_SALT_LENGTH] = {
  0x05, 0xe7, 0xd7, 0xc2, 0x4e, 0xb5, 0xfe, 0x7c,
  0x31, 0xe6, 0x73, 0xb4, 0x27, 0x76, 0xee, 0xa8,
  0xc8, 0x9b, 0xfe, 0x4d, 0x5b, 0xaf, 0x5c, 0x05,
  0xe2, 0x6b, 0xe7, 0x75, 0xb4, 0x3b, 0x7a, 0x2b
};

static const unsigned char cred_id_buffer[8] = {
  0x70, 0x6c, 0x61, 0x73, 0x74, 0x69, 0x63, 0x0a
};
static const bytes_t cred_id = BYTESINIT(
  (unsigned char*)cred_id_buffer, sizeof(cred_id_buffer));
static const char *cred_id_b64 = "cGxhc3RpYwo=";

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

typedef struct {
  char af_path[260];
  int argc;
  char **argv;
  cfg_t cfg;
  uid_t uid;
  char *user;
  device_t *dev;
  unsigned n_dev;
  char *af_content;
} context_t;

static context_t *open_context(const char *caller) {
  context_t *c = calloc(1, sizeof(context_t));
  assert(NULL != c);

  snprintf(c->af_path, sizeof(c->af_path), "/tmp/%s%lx", caller, lrand48());

  c->argc = 1;
  c->argv = calloc(c->argc, sizeof(char*));
  assert(NULL != c->argv);
  assert(asprintf(&c->argv[0], "authfile=%s", c->af_path) > 0);

  assert(PAM_SUCCESS == cfg_init(&c->cfg, 0, c->argc, (const char**)c->argv, caller));

  c->uid = getuid();
  struct passwd *pw = getpwuid(c->uid);
  assert(NULL != pw && "Failed to get user info from uid");
  assert(NULL != pw->pw_name);
  assert(strlen(pw->pw_name) > 0);
  c->user = strdup(pw->pw_name);

  c->cfg.max_devs = MAX_DEVS;
  c->dev = calloc(c->cfg.max_devs, sizeof(device_t));
  assert(NULL != c->dev && "Failed to allocate device_t array");
  c->n_dev = 0;

  log_info(c->cfg.log, "Running");

  return c;
}

static void close_context(context_t *c) {
  free(c->af_content);
  free_devices(c->dev, c->n_dev);
  free(c->user);
  cfg_free(&c->cfg);
  for (int i = 0; i < c->argc; i++)
    free(c->argv[i]);
  free(c->argv);
  unlink(c->af_path);
  free(c);
}

#define PASSWORD      "old-password"
#define NEW_PASSWORD  "__new__password__"

static char *read_authfile(const char *path) {
  FILE *f = fopen(path, "r");
  assert(NULL != f && "Failed to open authfile for reading");

  assert(0 == fseek(f, 0, SEEK_END));
  const long size = ftell(f);
  assert(size >= 0 && "Failed to get authfile size");

  assert(0 == fseek(f, 0, SEEK_SET));
  char *content = malloc(size + 1);
  assert(NULL != content && "Failed to allocate authfile read buffer");

  assert((const size_t)size == fread(content, 1, size, f));
  content[size] = '\0';

  return content;
}

static bool is_authfile_same(context_t *c) {
  char *content = read_authfile(c->af_path);
  bool is_same = 0 == strcmp(content, c->af_content);
  free(content);
  return is_same;
}

static void write_user(FILE *f, context_t *c, const char *user, 
                       const char *password) {
  char *ep;
  assert(encrypt_password(c->cfg.log, user, cred_id, hmac_salt, 
    hmac_secret, password, &ep));
  assert(EOF != fputs(user, f));
  assert(fprintf(f, ":%s,abcd,es256,+presence,%s", cred_id_b64, ep) > 0);
  assert(EOF != fputs(":abcd,abcd,es256,+presence,*\n", f));
  free(ep);
}

static void write_user_ljenkins(FILE *f) {
  assert(EOF != fputs("ljenkins:probability=0.32333,type=whelps\n", f));
}

static void write_user_hopper(FILE *f) {
  assert(EOF != fputs("hopper:\n", f));
}

static void create_authfile_ex(context_t *c, const char *user,
                               const char *password) {
  FILE *f = fopen(c->af_path, "w+");
  assert(NULL != f && "Failed to create temp authfile");
  write_user_ljenkins(f);
  write_user(f, c, user, password);
  write_user_hopper(f);
  assert(0 == fclose(f));

  free(c->af_content);
  c->af_content = read_authfile(c->af_path);
}

static void create_authfile(context_t *c) {
  create_authfile_ex(c, c->user, PASSWORD);
}

/*
 * Test Cases 
 */

static void test_update_authfile_user_succeeds(void) {
  context_t *c = open_context(__func__);
  create_authfile(c);
  assert(PAM_SUCCESS == update_authfile_user(&c->cfg, c->user, c->dev,
    &c->n_dev, PASSWORD, NEW_PASSWORD));
  assert(!is_authfile_same(c));
  close_context(c);
}

static void test_update_authfile_user_fails_file_uid_mismatch(void) {
  context_t *c = open_context(__func__);
  create_authfile(c);
  assert(PAM_AUTHINFO_UNAVAIL == update_authfile_user(&c->cfg, "_alice_", 
    c->dev, &c->n_dev, PASSWORD, NEW_PASSWORD));
  assert(is_authfile_same(c));
  close_context(c);
}

static void test_update_authfile_user_succeeds_no_change_bad_password(void) {
  context_t *c = open_context(__func__);
  create_authfile(c);
  assert(PAM_SUCCESS == update_authfile_user(&c->cfg, c->user, c->dev,
    &c->n_dev, "wrong-old-password", NEW_PASSWORD));
  assert(is_authfile_same(c));
  close_context(c);
}

static void test_update_authfile_user_succeeds_no_change_sshformat(void) {
  context_t *c = open_context(__func__);
  create_authfile(c);
  c->cfg.sshformat = 1;
  assert(PAM_SUCCESS == update_authfile_user(&c->cfg, c->user, c->dev,
    &c->n_dev, PASSWORD, NEW_PASSWORD));
  assert(is_authfile_same(c));
  close_context(c);
}

static void test_update_authfile_user_succeeds_empty_old_password(void) {
  context_t *c = open_context(__func__);
  create_authfile_ex(c, c->user, NULL);
  assert(PAM_SUCCESS == update_authfile_user(&c->cfg, c->user, c->dev,
    &c->n_dev, NULL, NEW_PASSWORD));
  assert(!is_authfile_same(c));
  close_context(c);
}

static void test_update_authfile_user_succeeds_empty_new_password(void) {
  context_t *c = open_context(__func__);
  create_authfile(c);
  assert(PAM_SUCCESS == update_authfile_user(&c->cfg, c->user, c->dev,
    &c->n_dev, PASSWORD, NULL));
  assert(!is_authfile_same(c));
  close_context(c);
}

static void test_update_authfile_user_succeeds_no_change_user_not_in_authfile(void) {
  context_t *c = open_context(__func__);
  create_authfile_ex(c, "_bob_", PASSWORD);
  assert(PAM_SUCCESS == update_authfile_user(&c->cfg, c->user, c->dev,
    &c->n_dev, PASSWORD, NEW_PASSWORD));
  assert(is_authfile_same(c));
  close_context(c);
}

static void test_update_authfile_user_succeeds_user_is_last_entry(void) {
  context_t *c = open_context(__func__);
  FILE *f = fopen(c->af_path, "w+");
  assert(NULL != f && "Failed to create temp authfile");
  write_user_ljenkins(f);
  write_user_hopper(f);
  write_user(f, c, c->user, PASSWORD);
  assert(0 == fclose(f));
  c->af_content = read_authfile(c->af_path);

  assert(PAM_SUCCESS == update_authfile_user(&c->cfg, c->user, c->dev,
    &c->n_dev, PASSWORD, NEW_PASSWORD));

  assert(!is_authfile_same(c));
  close_context(c);
}

static void test_update_authfile_user_succeeds_user_is_first_entry(void) {
  context_t *c = open_context(__func__);
  FILE *f = fopen(c->af_path, "w+");
  assert(NULL != f && "Failed to create temp authfile");
  write_user(f, c, c->user, PASSWORD);
  write_user_ljenkins(f);
  write_user_hopper(f);
  assert(0 == fclose(f));
  c->af_content = read_authfile(c->af_path);

  assert(PAM_SUCCESS == update_authfile_user(&c->cfg, c->user, c->dev,
    &c->n_dev, PASSWORD, NEW_PASSWORD));

  assert(!is_authfile_same(c));
  close_context(c);
}

static void test_update_authfile_user_succeeds_user_has_two_entries_only_last_one_changes(void) {
  context_t *c = open_context(__func__);
  FILE *f = fopen(c->af_path, "w+");
  assert(NULL != f && "Failed to create temp authfile");
  write_user_ljenkins(f);
  write_user(f, c, c->user, PASSWORD);
  write_user(f, c, c->user, PASSWORD);
  write_user_hopper(f);
  assert(0 == fclose(f));
  c->af_content = read_authfile(c->af_path);

  const char *orig_last_user = strstr(c->af_content, c->user);
  assert(NULL != orig_last_user);
  orig_last_user = strstr(orig_last_user + strlen(c->user), c->user);
  assert(NULL != orig_last_user);

  assert(PAM_SUCCESS == update_authfile_user(&c->cfg, c->user, c->dev,
    &c->n_dev, PASSWORD, NEW_PASSWORD));

  char *content = read_authfile(c->af_path);
  const char *last_user = strstr(content, c->user);
  assert(NULL != last_user);
  last_user = strstr(last_user + strlen(c->user), c->user);
  assert(NULL != last_user);

  assert(last_user - content == orig_last_user - c->af_content);
  assert(0 == strncmp(c->af_content, content, last_user - content));
  assert(0 != strcmp(orig_last_user, last_user));

  free(content);
  close_context(c);
}

static void test_update_authfile_user_succeeds_no_change_user_has_no_passwords(void) {
  context_t *c = open_context(__func__);
  FILE *f = fopen(c->af_path, "w+");
  assert(NULL != f && "Failed to create temp authfile");
  write_user_ljenkins(f);
  assert(fprintf(f, "%s:1234,abcd,es256,+presence\n", c->user) > 0);
  write_user_hopper(f);
  assert(0 == fclose(f));
  c->af_content = read_authfile(c->af_path);

  assert(PAM_SUCCESS == update_authfile_user(&c->cfg, c->user, c->dev,
    &c->n_dev, PASSWORD, NEW_PASSWORD));

  assert(is_authfile_same(c));
  close_context(c);
}

static void test_update_authfile_user_succeeds_no_change_user_has_no_credentials(void) {
  context_t *c = open_context(__func__);
  FILE *f = fopen(c->af_path, "w+");
  assert(NULL != f && "Failed to create temp authfile");
  write_user_ljenkins(f);
  assert(fprintf(f, "%s:\n", c->user) > 0);
  write_user_hopper(f);
  assert(0 == fclose(f));
  c->af_content = read_authfile(c->af_path);

  assert(PAM_SUCCESS == update_authfile_user(&c->cfg, c->user, c->dev,
    &c->n_dev, PASSWORD, NEW_PASSWORD));

  assert(is_authfile_same(c));
  close_context(c);
}

int main(void) {
  srand48(time(NULL));

  test_update_authfile_user_succeeds();
  test_update_authfile_user_fails_file_uid_mismatch();
  test_update_authfile_user_succeeds_no_change_bad_password();
  test_update_authfile_user_succeeds_no_change_sshformat();
  test_update_authfile_user_succeeds_empty_old_password();
  test_update_authfile_user_succeeds_empty_new_password();
  test_update_authfile_user_succeeds_no_change_user_not_in_authfile();
  test_update_authfile_user_succeeds_user_is_last_entry();
  test_update_authfile_user_succeeds_user_is_first_entry();
  test_update_authfile_user_succeeds_user_has_two_entries_only_last_one_changes();
  test_update_authfile_user_succeeds_no_change_user_has_no_passwords();
  test_update_authfile_user_succeeds_no_change_user_has_no_credentials();

  return 0;
}
