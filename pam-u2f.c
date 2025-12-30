/*
 *  Copyright (C) 2014-2023 Yubico AB - See COPYING
 */

/* Define which PAM interfaces we provide */
#define PAM_SM_AUTH

/* Include PAM headers */
#include <security/pam_appl.h>
#include <security/pam_modules.h>

#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdint.h>
#include <stdlib.h>
#include <syslog.h>
#include <pwd.h>
#include <string.h>
#include <errno.h>

#include "b64.h"
#include "crypt.h"
#include "drop_privs.h"
#include "log.h"
#include "util.h"

#define free_const(a) free((void *) (uintptr_t) (a))
#define LOG_PREFIX "debug(pam_u2f)"

/* If secure_getenv is not defined, define it here */
#ifndef HAVE_SECURE_GETENV
char *secure_getenv(const char *);
char *secure_getenv(const char *name) {
  (void) name;
  return NULL;
}
#endif

static void interactive_prompt(pam_handle_t *pamh, const cfg_t *cfg) {
  char *tmp = NULL;

  tmp = converse(pamh, PAM_PROMPT_ECHO_ON,
                 cfg->prompt != NULL ? cfg->prompt : DEFAULT_PROMPT);

  free(tmp);
}

static char *resolve_authfile_path(const log_t *log, const cfg_t *cfg, 
                                   const struct passwd *user,
                                   int *openasuser) {
  char *authfile = NULL;
  const char *dir = NULL;
  const char *path = NULL;

  *openasuser = geteuid() == 0; /* user files, drop privileges */

  if (cfg->auth_file == NULL) {
    if ((dir = secure_getenv(DEFAULT_AUTHFILE_DIR_VAR)) == NULL) {
      log_trace(log, "Variable %s is not set, using default",
                     DEFAULT_AUTHFILE_DIR_VAR);
      dir = user->pw_dir;
      path = cfg->sshformat ? DEFAULT_AUTHFILE_DIR_SSH "/" DEFAULT_AUTHFILE_SSH
                            : DEFAULT_AUTHFILE_DIR "/" DEFAULT_AUTHFILE;
    } else {
      log_trace(log, "Variable %s set to %s", DEFAULT_AUTHFILE_DIR_VAR, dir);
      *openasuser = 0; /* documented exception, require explicit openasuser */
      path = cfg->sshformat ? DEFAULT_AUTHFILE_SSH : DEFAULT_AUTHFILE;
      if (!cfg->openasuser) {
        log_warn(log, "not dropping privileges when reading the "
                      "authentication file, please consider setting "
                      "openasuser=1 in the module configuration");
      }
    }
  } else {
    dir = user->pw_dir;
    path = cfg->auth_file;
  }

  if (dir == NULL || *dir != '/' || path == NULL ||
      asprintf(&authfile, "%s/%s", dir, path) == -1)
    authfile = NULL;

  return authfile;
}

static FILE *open_log_file(const char *filename, bool *is_console_file) {
  struct stat st;
  FILE *file;
  int fd;

  *is_console_file = false;

  if (!filename) {
    is_console_file = true;
    return stderr;
  }
  if (strcmp(filename, "stdout") == 0) {
    is_console_file = true;
    return stdout;
  }
  if (strcmp(filename, "stderr") == 0) {
    is_console_file = true;
    return stderr;
  }
  if (strcmp(filename, "syslog") == 0)
    return NULL;

  fd = open(filename, O_WRONLY | O_APPEND | O_CLOEXEC | O_NOFOLLOW | O_NOCTTY);
  if (fd == -1 || fstat(fd, &st) != 0)
    goto err;

#ifndef WITH_FUZZING
  if (!S_ISREG(st.st_mode))
    goto err;
#endif

  if ((file = fdopen(fd, "a")) != NULL)
    return file;

err:
  if (fd != -1)
    close(fd);

  *is_console_file = true;
  return stderr; /* fallback to default */
}

static void close_log_file(FILE *f) {
  if (f != NULL && f != stdout && f != stderr)
    fclose(f);
}

typedef struct pam_api_context {
  pam_handle_t *pamh;
  int flags;
  int argc;
  char **argv;

  cfg_t cfg;
  char *buffer_origin;
  char *buffer_appid;
  char *buffer_auth_file;
  char *buffer_authpending_file;

  FILE *log_file;
  log_t *log;

  device_t *devices;
  size_t devices_len;

  const char *user;
  struct passwd *pass;
  char *buffer_pass;

  int open_authfile_as_user;
} pam_api_context_t;

bool init_pam_api_context(const char *api_name, pam_handle_t *pamh, 
  int flags, int argc, const char **argv, pam_api_context_t *ctx)
{
  int result = PAM_ABORT;
  cfg_t *cfg = NULL;
  bool log_is_using_console = false;
  log_level_t minimum_level;
  log_t *log = NULL;
  struct passwd *pw_s;

  memset(ctx, 0, sizeof(*ctx));
  ctx->pamh = pamh;
  ctx->flags = flags;
  ctx->argc = argc;
  ctx->argv = argv;

  result = cfg_init(&ctx->cfg, flags, argc, argv);
  if (result != PAM_SUCCESS)
    goto err;

  cfg = &ctx->cfg;

  ctx->log_file = open_log_file(ctx->cfg.debug_file, &log_is_using_console);
  minimum_level = ctx->cfg.debug ? log_level_trace : log_level_info;
 
  // When PAM_SILENT is set, we aren't allowed to log to the console.
  if (0 == (flags & PAM_SILENT) || !log_is_using_console) {
    ctx->log = ctx->log_file ? 
      log_create_using_file(minimum_level, LOG_PREFIX, ctx->log_file) :
      log_create_using_syslog(minimum_level, LOG_PREFIX, LOG_AUTHPRIV);
    
    log = ctx->log;
  }
 
  log_trace(log, "%s: flags %d argc %d", api_name, flags, argc);
  for (int i = 0; i < argc; i++)
    log_trace(log, "argv[%d]=%s", i, argv[i]);
  cfg_log(log, cfg);

  if (!cfg->origin) {
    char buffer[BUFSIZE];

    if (!cfg->sshformat) {
      strcpy(buffer, DEFAULT_ORIGIN_PREFIX);
      if (gethostname(buffer + strlen(DEFAULT_ORIGIN_PREFIX),
                      BUFSIZE - strlen(DEFAULT_ORIGIN_PREFIX)) == -1) {
        log_error(log, "Unable to get host name");
        result = PAM_SYSTEM_ERR;
        goto err;
      }
    } else {
      strcpy(buffer, SSH_ORIGIN);
    }

    log_trace(log, "Origin not specified, using \"%s\"", buffer);
    ctx->buffer_origin = strdup(buffer);
    if (!ctx->buffer_origin) {
      log_error(log, "Unable to allocate memory");
      result = PAM_BUF_ERR;
      goto err;
    }

    cfg->origin = ctx->buffer_origin;
  }

  if (!cfg->appid) {
    log_trace(log, "Appid not specified, using the value of origin (%s)",
                   cfg->origin);
    ctx->buffer_appid = strdup(cfg->origin);
    if (!ctx->buffer_appid) {
      log_error(log, "Unable to allocate memory");
      result = PAM_BUF_ERR;
      goto err;
    }

    cfg->appid = ctx->buffer_appid;
  }

  if (0 == cfg->max_devs) {
    log_trace(log, "Maximum number of devices not set. Using default (%d)",
                   MAX_DEVS);
    cfg->max_devs = MAX_DEVS;
  }
#if WITH_FUZZING
  if (cfg->max_devs > 256)
    cfg->max_devs = 256;
#endif

  ctx->devices = calloc(ctx->devices_len, sizeof(device_t));
  if (!ctx->devices) {
    log_error(log, "Unable to allocate memory");
    result = PAM_BUF_ERR;
    goto err;
  }
  ctx->devices_len = cfg->max_devs;

  result = pam_get_user(pamh, &ctx->user, NULL);
  if (PAM_SUCCESS != result) {
    log_error(log, "pam_get_user: %s (%d)", 
              pam_strerror(pamh, result), result);
    goto err;
  }
  if (!ctx->user || '\0' == ctx->user[0]) {
    log_error(log, "pam_get_user returned an empty user name");
    result = PAM_AUTH_ERR;
    goto err;
  }

  log_trace(log, "Requesting authentication for user %s", ctx->user);

  if (!(ctx->buffer_pass = malloc(BUFSIZE))) {
    log_error(log, "Unable to allocate memory");
    result = PAM_BUF_ERR;
    goto err;
  }

  result = getpwnam_r(ctx->user, &pw_s, ctx->buffer_pass, BUFSIZE, 
    &ctx->pass);
  if (result != 0 || ctx->pass == NULL || ctx->pass->pw_dir == NULL ||
      ctx->pass->pw_dir[0] != '/') {
    log_error(log,
              "Unable to retrieve credentials for user %s: %s (%d)", 
              ctx->user, strerror(errno), errno);
    result = PAM_SYSTEM_ERR;
    goto err;
  }

  log_trace(log, "Found user %s", ctx->user);
  log_trace(log, "Home directory for %s is %s", ctx->user, ctx->pass->pw_dir);

  // Perform variable expansion.
  if (cfg->expand && cfg->auth_file) {
    ctx->buffer_auth_file = expand_variables(cfg->auth_file, ctx->user);
    if (!ctx->buffer_auth_file) {
      log_error(log, "Failed to perform variable expansion");
      return PAM_BUF_ERR;
    }
    cfg->auth_file = ctx->buffer_auth_file;
  }

  // Resolve default or relative paths.
  if (!cfg->auth_file || cfg->auth_file[0] != '/') {
    char *tmp = resolve_authfile_path(log, cfg, ctx->pass, 
      &ctx->open_authfile_as_user);
    if (tmp == NULL) {
      log_error(log, "Could not resolve authfile path");
      return PAM_BUF_ERR;
    }
    free(ctx->buffer_auth_file);
    ctx->buffer_auth_file = tmp;

    cfg->auth_file = ctx->buffer_auth_file;
  }
  if (!ctx->open_authfile_as_user)
    ctx->open_authfile_as_user = geteuid() == 0 && cfg->openasuser;

  result = PAM_SUCCESS;

err:
  return result;
}

void cleanup_pam_api_context(pam_api_context_t *ctx)
{
  if (ctx) {
    free(ctx->buffer_pass);
    free_devices(ctx->devices, ctx->devices_len);
    log_destroy(ctx->log);
    close_log_file(ctx->log_file);
    free(ctx->buffer_authpending_file);
    free(ctx->buffer_auth_file);
    free(ctx->buffer_appid);
    free(ctx->buffer_origin);
    cfg_free(&ctx->cfg);

    memset(ctx, 0, sizeof(*ctx));
  }
}

/* PAM entry point for authentication verification */
int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc,
                        const char **argv) 
{

  int retval = PAM_ABORT;
  pam_api_context_t ctx;
  cfg_t *cfg = NULL;
  log_t *log = NULL;
  PAM_MODUTIL_DEF_PRIVS(privs);

  retval = init_pam_api_context(__func__, pamh, flags, argc, argv, &ctx);
  if (PAM_SUCCESS != retval)
    goto done;

  cfg = &ctx.cfg;
  log = ctx.log;

  log_trace(log, "Using authentication file %s", cfg->auth_file);

  if (ctx.open_authfile_as_user) {
    log_trace(log, "Dropping privileges");
    if (pam_modutil_drop_priv(ctx.pamh, &privs, ctx.pass)) {
      log_error(log, "Unable to switch user to uid %i", ctx.pass->pw_uid);
      retval = PAM_SYSTEM_ERR;
      goto done;
    }
    log_trace(log, "Switched to uid %i", ctx.pass->pw_uid);
  }

  retval = get_devices_from_authfile(log, cfg, ctx.user, 
    ctx.devices, &ctx.devices_len);

  if (ctx.open_authfile_as_user) {
    if (pam_modutil_regain_priv(ctx.pamh, &privs)) {
      log_error(log, "could not restore privileges");
      retval = PAM_SYSTEM_ERR;
      goto done;
    }
    log_trace(log, "Restored privileges");
  }

  if (PAM_SUCCESS != retval)
    goto done;

  // Determine the full path for authpending_file in order to emit touch request
  // notifications
  if (!cfg->authpending_file) {
    char buffer[BUFSIZE];
    int actual_size =
      snprintf(buffer, BUFSIZE, DEFAULT_AUTHPENDING_FILE_PATH, getuid());
    if (actual_size >= 0 && actual_size < BUFSIZE) {
      ctx.buffer_authpending_file = strdup(buffer);
    }
    cfg->authpending_file = ctx.buffer_authpending_file;
    if (!cfg->authpending_file) {
      log_error(log, "Unable to allocate memory for the authpending_file, "
                     "touch request notifications will not be emitted");
    }
  } else {
    if (strlen(cfg->authpending_file) == 0) {
      log_trace(log, "authpending_file is set to an empty value, touch request "
                     "notifications will be disabled");
      cfg->authpending_file = NULL;
    }
  }

  int authpending_file_descriptor = -1;
  if (cfg->authpending_file) {
    log_trace(log, "Touch request notifications will be emitted via '%s'",
                   cfg->authpending_file);

    // Open (or create) the authpending_file to indicate that we start waiting
    // for a touch
    authpending_file_descriptor =
      open(cfg->authpending_file,
           O_RDONLY | O_CREAT | O_CLOEXEC | O_NOFOLLOW | O_NOCTTY, 0664);
    if (authpending_file_descriptor < 0) {
      log_warn(log, "Unable to emit 'authentication started' notification: %s",
                    strerror(errno));
    }
  }

  if (cfg->manual == 0) {
    if (cfg->interactive) {
      interactive_prompt(pamh, cfg);
    }
    retval = do_authentication(log, cfg, ctx.user, ctx.devices, 
      ctx.devices_len, pamh);
  } else {
    retval = do_manual_authentication(log, cfg, ctx.devices, ctx.devices_len, 
      pamh);
  }

  // Close the authpending_file to indicate that we stop waiting for a touch
  if (authpending_file_descriptor >= 0) {
    if (close(authpending_file_descriptor) < 0) {
      log_warn(log, "Unable to emit 'authentication stopped' notification: %s",
                    strerror(errno));
    }
  }

done:
  if (cfg->alwaysok && retval != PAM_SUCCESS) {
    log_trace(log, "alwaysok needed (otherwise return with %d)", retval);
    retval = PAM_SUCCESS;
  }
  log_trace(log, "done. [%s]", pam_strerror(pamh, retval));

  cleanup_pam_api_context(&ctx);

  return retval;
}

int update_encrypted_passwords(pam_api_context_t *ctx, 
  const char *old_password, const char *new_password) 
{
  int result = PAM_AUTH_ERR;
  cfg_t *cfg = &ctx->cfg;
  log_t *log = ctx->log;
  char **encrypted_passwords = NULL;
  size_t encrypted_passwords_len = 0;
  unsigned char *cred_id_ptr = NULL;
  size_t cred_id_len;
  bool dirty = false;

  result = get_devices_from_authfile(log, cfg, ctx->user, ctx->devices,
    &ctx->devices_len);
  if (PAM_SUCCESS != result)
    goto err;

  encrypted_passwords_len = ctx->devices_len;
  encrypted_passwords = calloc(ctx->devices_len, sizeof(char*));
  if (!encrypted_passwords) {
    result = PAM_BUF_ERR;
    goto err;
  }

  for (size_t index = 0; index < ctx->devices_len; index++) {
    device_t *device = &ctx->devices[index];
    const char *ep = device->encryptedPassword;

    if (device->old_format)
      continue;
    if (!ep || '\0' == ep[0] || 0 == strcmp(ep, "*"))
      continue;

    free(cred_id_ptr);
    cred_id_ptr = NULL;

    if (!b64_decode(device->keyHandle, strlen(device->keyHandle), 
        &cred_id_ptr, &cred_id_len)) {
      result = PAM_AUTHINFO_UNAVAIL;
      goto err;
    }

    if (!update_encrypted_password(log, old_password, new_password, ctx->user,
        cred_id_ptr, cred_id_len, ep, &encrypted_passwords[index])) {
      result = PAM_AUTH_ERR;
      goto err;
    }
    dirty = true;
  }

  if (dirty) {

#error here -- need to rework the file-reading code so it can be used for both reading and writing

    // scan the entire file
    //   find the last line for this user ==> this is the one we're going to replace 
    //   (note the file positions at the start (first char) and end (pos of \n + 1) of this line)
    //
    // create a new temp file next to the one we are renaming -- .tmpXXXXX
    //   write(read(up-to-start-pos))
    //
    //   write the replacement line
    //
    //      user:devices[0]:devices[1]:...:devices[n]
    //         device[i] (old_format)  = keyHandle,publicKey
    //                   (!old_format) = keyHandle,publicKey,coseType,attributes,encryptedPassword
    //
    //   write(read(from-end-pos-to-EOF))
    //   on error, delete .tmpXXXXX
    //   on success, move .tmpXXXXX overtop of authfile (atomic replace)
  }

  result = PAM_SUCCESS;

err:
  if (encrypted_passwords) {
    for (size_t i = 0; i < encrypted_passwords_len; i++)
      free(encrypted_passwords[i]);
    free(encrypted_passwords);
  }
  free(cred_id_ptr);
  return result;
}

PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc,
                              const char **argv) {
  (void) pamh;
  (void) flags;
  (void) argc;
  (void) argv;

  return PAM_SUCCESS;
}

/* Password Management */
int pam_sm_chauthtok(pam_handle_t *pamh, int flags, 
  int argc, const char **argv)
{
  int result = PAM_AUTHTOK_ERR;
  pam_api_context_t ctx;
  cfg_t *cfg = NULL;
  log_t *log = NULL;
  const char *old_password;
  const char *new_password;
  PAM_MODUTIL_DEF_PRIVS(privs);

  result = init_pam_api_context(__func__, pamh, flags, argc, argv, &ctx);
  if (PAM_SUCCESS != result)
    goto err;

  cfg = &ctx.cfg;
  log = ctx.log;

  // System wants us to verify that we are able to do a password update.
  // We have no external dependencies, so this is always true.
  if (flags & PAM_PRELIM_CHECK) {
    log_trace(log, "PAM_PRELIM_CHECK successful");
    result = PAM_SUCCESS;
    goto err;
  }

  // System is requesting that we only update expired passwords. Our 
  // passwords never expire, so there is no action we can take.
  if (flags & PAM_CHANGE_EXPIRED_AUTHTOK) {
    log_trace(log, 
              "PAM_CHANGE_EXPIRED_AUTHTOK successful. "
              "U2F passwords do not expire. No changes were made.");
    result = PAM_SUCCESS;
    goto err;
  }

  if (flags & PAM_UPDATE_AUTHTOK) {
    log_trace(log, "Processing PAM_UPDATE_AUTHTOK");

    if (0 != cfg->sshformat) {
      log_warn(log, 
               "Ignoring password-change request for SSH-format authfile %s",
                cfg->auth_file);
      result = PAM_SUCCESS;
      goto err;
    }

    result = pam_get_item(pamh, PAM_OLDAUTHTOK, &old_password);
    if (PAM_SUCCESS != result) {
      log_error(log, "pam_get_item(PAM_OLDAUTHTOK): %s (%d)", 
                pam_strerror(pamh, result), result);
      goto err;
    }

    result = pam_get_item(pamh, PAM_AUTHTOK, &new_password);
    if (PAM_SUCCESS != result) {
      log_error(log, "pam_get_item(PAM_AUTHTOK): %s (%d)", 
                pam_strerror(pamh, result), result);
      goto err;
    }

    log_trace(log, "Using authentication file %s", cfg->auth_file);

    if (ctx.open_authfile_as_user) {
      log_trace(log, "Dropping privileges");
      if (pam_modutil_drop_priv(ctx.pamh, &privs, ctx.pass)) {
        log_error(log, "Unable to switch user to uid %i", ctx.pass->pw_uid);
        result = PAM_SYSTEM_ERR;
        goto err;
      }
      log_trace(log, "Switched to uid %i", ctx.pass->pw_uid);
    }

    result = update_encrypted_passwords(&ctx, old_password, new_password);

    if (ctx.open_authfile_as_user) {
      if (pam_modutil_regain_priv(ctx.pamh, &privs)) {
        log_error(log, "could not restore privileges");
        result = PAM_SYSTEM_ERR;
        goto err;
      }
      log_trace(log, "Restored privileges");
    }

    if (PAM_SUCCESS != result)
      goto err;
  }

  result = PAM_SUCCESS;

err:
  cleanup_pam_api_context(&ctx);
  return result;
}


#ifdef PAM_MODULE_ENTRY
PAM_MODULE_ENTRY("pam_u2f")
#endif
