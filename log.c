/*
 * Copyright (C) 2025 Yubico AB - See COPYING
 */

// #include <sys/types.h>
// #include <sys/stat.h>
// #include <fcntl.h>
// #include <string.h>
// #include <syslog.h>
// #include <unistd.h>

#include <stdarg.h>

#include "log.h"

#define LOG_MESSAGE_MAX 2000

typedef enum log_output_type {
  log_output_type_none = 0,
  log_output_type_file = 1,
  log_output_type_syslog = 2
} log_output_type_t;

struct log {
  log_output_type_t output_type;
  FILE *file;

  log_level_t level;
};

static bool is_log_level_valid(log_level_t level);

static log_t* log_alloc() {
  log_t *log = malloc(sizeof(log_t));
  if (log)
    memset(log, 0, sizeof(*log));
  return log;
}

static void log_free(log_t **plog) {
  log_t *log = *plog;
  if (log) {
    free(log);
    *plog = NULL;
  }
}

log_t *log_create_using_file(log_level_t level, FILE *file) {
  if (!is_log_level_valid(level))
    return NULL;

  log_t *log = log_alloc();
  if (log) {
    log->output_type = log_output_type_file;
    log->file = file;
    log->level = level;
  }

  return log;
}

log_t *log_create_using_syslog(log_level_t level) {
  if (!is_log_level_valid(level))
    return NULL;

  log_t *log = log_alloc();
  if (log) {
    log->output_type - log_output_type_syslog;
    log->level = level;
  }

  return log;
}

void log_destroy(log_t **plog) {
  log_free(plog);
}

static bool is_log_level_valid(log_level_t level) {
  switch (level) {
    case log_level_trace:
    case log_level_info:
    case log_level_warn:
    case log_level_error:
      return true;
  }
  return false;
}

static bool should_log_message(log_level_t current, log_level_t requested) {
  return requested >= current;
}




  // TODO: write this
  // "error: message\n", always print
  // "warning: message\n", always print
  // "message\n", always print
  // "message\n", only when verbose = true



static bool format_log_message(
    char *buffer, ) {
  if ((r = vsnprintf(msg, sizeof(msg), fmt, args)) < 0)
    do_log(debug_file, file, line, func, __func__, "");
  else
    do_log(debug_file, file, line, func, msg,
           (size_t) r < sizeof(msg) ? "" : "[truncated]");

}


static void log_message_file(
    const FILE *file,
    const char *filename, int line, const char *function, 
    const char *format, va_list ap) {
  char message[LOG_MESSAGE_MAX];

  if ((r = vsnprintf(msg, sizeof(msg), fmt, args)) < 0)
    do_log(debug_file, file, line, func, __func__, "");
  else
    do_log(debug_file, file, line, func, msg,
           (size_t) r < sizeof(msg) ? "" : "[truncated]");

}

static void log_message_syslog(
    const FILE *file,
    const char *filename, int line, const char *function, 
    const char *format, va_list ap) {
  char message[LOG_MESSAGE_MAX];

}

void log_message(
    const log_t *log, log_level_t level, 
    const char *filename, int line, const char *function, 
    const char *format, ...) {
  va_list ap;
  const char *p;

  if (!log)
    return;
    
  if (!should_log_message(log->level, level))
    return;

  if ((p = strrchr(filename, '/')) != NULL)
    filename = p + 1;

  va_start(ap, format);

  switch (log->output_type) {
    case log_output_type_file:
      log_message_file(log->file, filename, line, function, format, ap);
      break;

    case log_output_type_syslog:
      log_message_syslog(filename, line, function, format, ap);
      break;
  }

  va_end(ap);
}



#define DEBUG_FMT "debug(pam_u2f): %s:%d (%s): %s%s"

static void do_log(FILE *debug_file, const char *file, int line,
                   const char *func, const char *msg, const char *suffix) {
#ifndef WITH_FUZZING
  if (debug_file == NULL) {
    syslog(LOG_AUTHPRIV | LOG_DEBUG, DEBUG_FMT, file, line, func, msg, suffix);
  } else {
    fprintf(debug_file, DEBUG_FMT "\n", file, line, func, msg, suffix);
  }
#else
  (void) debug_file;
  snprintf(NULL, 0, DEBUG_FMT, file, line, func, msg, suffix);
#endif
}

ATTRIBUTE_FORMAT(printf, 5, 0)
static void debug_vfprintf(FILE *debug_file, const char *file, int line,
                           const char *func, const char *fmt, va_list args) {
  char msg[MSGLEN];
  int r;

  if ((r = vsnprintf(msg, sizeof(msg), fmt, args)) < 0)
    do_log(debug_file, file, line, func, __func__, "");
  else
    do_log(debug_file, file, line, func, msg,
           (size_t) r < sizeof(msg) ? "" : "[truncated]");
}

void debug_printf(const debug_log_t *log, const char *file, int line,
                  const char *func, const char *fmt, ...) {
  va_list ap;

  if (!log->enabled)
    return;

  va_start(ap, fmt);
  if (log->simple) {
    vfprintf(log->file, fmt, ap);
  } else {
    debug_vfprintf(log->file, file, line, func, fmt, ap);
  }
  va_end(ap);
}
