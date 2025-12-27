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

static FILE *open_log_file(const char *filename) {
  struct stat st;
  FILE *file;
  int fd;

  if (!filename)
    return stderr;
  if (strcmp(filename, "stdout") == 0)
    return stdout;
  if (strcmp(filename, "stderr") == 0)
    return stderr;
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

  return stderr; /* fallback to default */
}

static void close_log_file(FILE *f) {
  if (f != NULL && f != stdout && f != stderr)
    fclose(f);
}

/* PAM entry point for authentication verification */
int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc,
                        const char **argv) {

  struct passwd *pw = NULL, pw_s;
  const char *user = NULL;
  cfg_t cfg_st;
  cfg_t *cfg = &cfg_st;
  FILE *log_file = NULL;
  log_level_t minimum_level;
  log_t *log = NULL;
  char buffer[BUFSIZE];
  int pgu_ret, gpn_ret;
  int retval = PAM_ABORT;
  device_t *devices = NULL;
  unsigned n_devices = 0;
  int openasuser = 0;
  int should_free_origin = 0;
  int should_free_appid = 0;
  int should_free_auth_file = 0;
  int should_free_authpending_file = 0;

  retval = cfg_init(cfg, flags, argc, argv);
  if (retval != PAM_SUCCESS)
    goto done;

  PAM_MODUTIL_DEF_PRIVS(privs);

  log_file = open_log_file(cfg->debug_file);
  minimum_level = cfg->debug ? log_level_trace : log_level_info;
  log = log_file ? 
          log_create_using_file(minimum_level, LOG_PREFIX, log_file) : 
          log_create_using_syslog(minimum_level, LOG_PREFIX, LOG_AUTHPRIV);
  log_trace(log, "flags %d argc %d", flags, argc);
  for (int i = 0; i < argc; i++)
    log_trace(log, "argv[%d]=%s", i, argv[i]);
  cfg_log(log, cfg);

  if (!cfg->origin) {
    if (!cfg->sshformat) {
      strcpy(buffer, DEFAULT_ORIGIN_PREFIX);
      if (gethostname(buffer + strlen(DEFAULT_ORIGIN_PREFIX),
                      BUFSIZE - strlen(DEFAULT_ORIGIN_PREFIX)) == -1) {
        log_error(log, "Unable to get host name");
        retval = PAM_SYSTEM_ERR;
        goto done;
      }
    } else {
      strcpy(buffer, SSH_ORIGIN);
    }
    log_trace(log, "Origin not specified, using \"%s\"", buffer);
    cfg->origin = strdup(buffer);
    if (!cfg->origin) {
      log_error(log, "Unable to allocate memory");
      retval = PAM_BUF_ERR;
      goto done;
    } else {
      should_free_origin = 1;
    }
  }

  if (!cfg->appid) {
    log_trace(log, "Appid not specified, using the value of origin (%s)",
                   cfg->origin);
    cfg->appid = strdup(cfg->origin);
    if (!cfg->appid) {
      log_error(log, "Unable to allocate memory");
      retval = PAM_BUF_ERR;
      goto done;
    } else {
      should_free_appid = 1;
    }
  }

  if (cfg->max_devs == 0) {
    log_trace(log, "Maximum number of devices not set. Using default (%d)",
                   MAX_DEVS);
    cfg->max_devs = MAX_DEVS;
  }
#if WITH_FUZZING
  if (cfg->max_devs > 256)
    cfg->max_devs = 256;
#endif

  devices = calloc(cfg->max_devs, sizeof(device_t));
  if (!devices) {
    log_error(log, "Unable to allocate memory");
    retval = PAM_BUF_ERR;
    goto done;
  }

  pgu_ret = pam_get_user(pamh, &user, NULL);
  if (pgu_ret != PAM_SUCCESS || user == NULL) {
    log_error(log, "Unable to get username from PAM");
    retval = PAM_CONV_ERR;
    goto done;
  }

  log_trace(log, "Requesting authentication for user %s", user);

  gpn_ret = getpwnam_r(user, &pw_s, buffer, sizeof(buffer), &pw);
  if (gpn_ret != 0 || pw == NULL || pw->pw_dir == NULL ||
      pw->pw_dir[0] != '/') {
    log_error(log, "Unable to retrieve credentials for user %s, (%s)", user,
                   strerror(errno));
    retval = PAM_SYSTEM_ERR;
    goto done;
  }

  log_trace(log, "Found user %s", user);
  log_trace(log, "Home directory for %s is %s", user, pw->pw_dir);

  // Perform variable expansion.
  if (cfg->expand && cfg->auth_file) {
    if ((cfg->auth_file = expand_variables(cfg->auth_file, user)) == NULL) {
      log_error(log, "Failed to perform variable expansion");
      retval = PAM_BUF_ERR;
      goto done;
    }
    should_free_auth_file = 1;
  }
  // Resolve default or relative paths.
  if (!cfg->auth_file || cfg->auth_file[0] != '/') {
    char *tmp = resolve_authfile_path(log, cfg, pw, &openasuser);
    if (tmp == NULL) {
      log_error(log, "Could not resolve authfile path");
      retval = PAM_BUF_ERR;
      goto done;
    }
    if (should_free_auth_file) {
      free_const(cfg->auth_file);
    }
    cfg->auth_file = tmp;
    should_free_auth_file = 1;
  }

  log_trace(log, "Using authentication file %s", cfg->auth_file);

  if (!openasuser) {
    openasuser = geteuid() == 0 && cfg->openasuser;
  }
  if (openasuser) {
    log_trace(log, "Dropping privileges");
    if (pam_modutil_drop_priv(pamh, &privs, pw)) {
      log_error(log, "Unable to switch user to uid %i", pw->pw_uid);
      retval = PAM_SYSTEM_ERR;
      goto done;
    }
    log_trace(log, "Switched to uid %i", pw->pw_uid);
  }
  retval = get_devices_from_authfile(log, cfg, user, devices, &n_devices);

  if (openasuser) {
    if (pam_modutil_regain_priv(pamh, &privs)) {
      log_error(log, "could not restore privileges");
      retval = PAM_SYSTEM_ERR;
      goto done;
    }
    log_trace(log, "Restored privileges");
  }

  if (retval != PAM_SUCCESS) {
    goto done;
  }

  // Determine the full path for authpending_file in order to emit touch request
  // notifications
  if (!cfg->authpending_file) {
    int actual_size =
      snprintf(buffer, BUFSIZE, DEFAULT_AUTHPENDING_FILE_PATH, getuid());
    if (actual_size >= 0 && actual_size < BUFSIZE) {
      cfg->authpending_file = strdup(buffer);
    }
    if (!cfg->authpending_file) {
      log_error(log, "Unable to allocate memory for the authpending_file, "
                     "touch request notifications will not be emitted");
    } else {
      should_free_authpending_file = 1;
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
    retval = do_authentication(log, cfg, devices, n_devices, pamh);
  } else {
    retval = do_manual_authentication(log, cfg, devices, n_devices, pamh);
  }

  // Close the authpending_file to indicate that we stop waiting for a touch
  if (authpending_file_descriptor >= 0) {
    if (close(authpending_file_descriptor) < 0) {
      log_warn(log, "Unable to emit 'authentication stopped' notification: %s",
                    strerror(errno));
    }
  }

done:
  free_devices(devices, n_devices);

  if (should_free_origin) {
    free_const(cfg->origin);
    cfg->origin = NULL;
  }

  if (should_free_appid) {
    free_const(cfg->appid);
    cfg->appid = NULL;
  }

  if (should_free_auth_file) {
    free_const(cfg->auth_file);
    cfg->auth_file = NULL;
  }

  if (should_free_authpending_file) {
    free_const(cfg->authpending_file);
    cfg->authpending_file = NULL;
  }

  if (cfg->alwaysok && retval != PAM_SUCCESS) {
    log_trace(log, "alwaysok needed (otherwise return with %d)", retval);
    retval = PAM_SUCCESS;
  }
  log_trace(log, "done. [%s]", pam_strerror(pamh, retval));

  log_destroy(&log);
  close_log_file(log_file);
  cfg_free(cfg);
  return retval;
}

PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc,
                              const char **argv) {
  (void) pamh;
  (void) flags;
  (void) argc;
  (void) argv;

  return PAM_SUCCESS;
}

#ifdef PAM_MODULE_ENTRY
PAM_MODULE_ENTRY("pam_u2f")
#endif
