/*
 * Copyright (C) 2025 Yubico AB - See COPYING
 */

#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>

#include "log.h"

#define LOG_MESSAGE_MAX 2000

typedef enum log_output_type {
  log_output_type_file,
  log_output_type_syslog
} log_output_type_t;

struct log {
  log_output_type_t output_type;
  FILE *file;
  int syslog_facility;

  log_level_t minimum_level;

  const char *prefix;
};

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

static const char *get_log_level_name(log_level_t level) {
  switch (level) {
    case log_level_error:
      return "ERROR";
    case log_level_warn:
      return "WARNING";
    case log_level_info:
      return "INFO";
    case log_level_trace:
      return "TRACE";
  }
  return NULL;
}

static int get_log_level_as_syslog_level(log_level_t level) {
  switch (level) {
    case log_level_trace:
      return LOG_DEBUG;
    case log_level_info:
      return LOG_INFO;
    case log_level_warn:
      return LOG_WARNING;
    case log_level_error:
      return LOG_ERR;
  }
  return LOG_INFO;
}

static log_t* log_alloc(void) {
  log_t *log = malloc(sizeof(log_t));
  if (log)
    memset(log, 0, sizeof(*log));
  return log;
}

static void log_free(log_t **plog) {
  log_t *log = *plog;
  if (log) {
    free((char*)log->prefix);
    free(log);
    *plog = NULL;
  }
}

log_t *log_create_using_file(log_level_t minimum_level, const char *prefix, FILE *file) {
  if (!is_log_level_valid(minimum_level))
    return NULL;
  if (!file)
    return NULL;

  log_t *log = log_alloc();
  if (log) {
    log->output_type = log_output_type_file;
    log->file = file;
    log->minimum_level = minimum_level;
    log->prefix = prefix ? strdup(prefix) : NULL;
  }

  return log;
}

log_t *log_create_using_syslog(log_level_t minimum_level, const char *prefix, int facility) {
  if (!is_log_level_valid(minimum_level))
    return NULL;

  log_t *log = log_alloc();
  if (log) {
    log->output_type = log_output_type_syslog;
    log->syslog_facility = facility & LOG_FACMASK;
    log->minimum_level = minimum_level;
    log->prefix = prefix ? strdup(prefix) : NULL;
  }

  return log;
}

void log_destroy(log_t **plog) {
  log_free(plog);
}

ATTRIBUTE_FORMAT(printf, 3, 0)
static size_t format_string_v(char *buffer, size_t length, const char *format, va_list ap) {
  int count = vsnprintf(buffer, length, format, ap);
  if (count < 0)
    count = 0;
  else if ((size_t)count > length)
    count = (int)length;

  if ((size_t)count < length)
    buffer[count] = '\0';

  return count;
}

ATTRIBUTE_FORMAT(printf, 3, 4)
static size_t format_string(char *buffer, size_t length, const char *format, ...) {
  va_list ap;
  size_t count;

  va_start(ap, format);
  count = format_string_v(buffer, length, format, ap);
  va_end(ap);

  return count;
}

ATTRIBUTE_FORMAT(printf, 8, 0)
static void format_log_message(
    char *buffer, size_t buffer_len,
    const char *prefix, 
    const char *filename, int line, const char *function,
    const char *level,
    const char *format, va_list ap) {

  size_t count;

  if (prefix) {
    count = format_string(buffer, buffer_len, "%s: ", prefix);
    buffer += count;
    buffer_len -= count;
  }
  if (filename && function) {
    count = format_string(buffer, buffer_len, "%s:%d (%s): ", filename, line, function);
    buffer += count;
    buffer_len -= count;
  }
  if (level) {
    count = format_string(buffer, buffer_len, "%s: ", level);
    buffer += count;
    buffer_len -= count;
  }
  format_string_v(buffer, buffer_len, format, ap);
}

ATTRIBUTE_FORMAT(printf, 6, 0)
static void log_message_internal(
    const log_t *log, log_level_t level, 
    const char *filename, int line, const char *function,
    const char *format, va_list ap) {

  char message[LOG_MESSAGE_MAX];

  if (log_output_type_file == log->output_type) {
    format_log_message(message, sizeof(message), log->prefix, filename, line, function, get_log_level_name(level), format, ap);
    fprintf(log->file, "%s\n", message);
  } else if (log_output_type_syslog == log->output_type) {
    format_log_message(message, sizeof(message), log->prefix, filename, line, function, NULL, format, ap);
    syslog(log->syslog_facility | get_log_level_as_syslog_level(level), "%s", message);
  }
}

static const char *get_basename(const char *filename) {
  const char *last_slash;

  if (!filename)
    return NULL;

  last_slash = strrchr(filename, '/');
  if (last_slash)
    return last_slash + 1;

  return filename;
}

void log_message(
    const log_t *log,
    const char *filename, int line, const char *function,
    log_level_t level, 
    const char *format, ...) {

  va_list ap;

  if (!log || level < log->minimum_level)
    return;

  va_start(ap, format);
  log_message_internal(log, level, get_basename(filename), line, function, format, ap);
  va_end(ap);
}
