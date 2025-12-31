/*
 * Copyright (C) 2025 Yubico AB - See COPYING
 */

#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>

#include "log.h"

#define LOG_MESSAGE_MAX 2000

struct log {
  log_output_type_t output_type;
  FILE *file;
  int syslog_facility;

  log_level_t minimum_level;

  const char *prefix;
};

#error reduce_churn: collapse these 3 routines away
#error reduce_churn: (a) use explicit values for all 4 levels so it is clear they are 1..4 and < and > work.
#error reduce_churn: (b) make a level_info struct w/string name and syslog level. then define 5 entries (1 per level), 1 per source line.

static bool is_log_level_valid(log_level_t level) {
  switch (level) {
    case log_level_trace:
    case log_level_info:
    case log_level_warn:
    case log_level_error:
      return true;
    default:
      return false;
  }
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
    default:
      return NULL;
  }
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
    default:
      return LOG_INFO;
  }
}

#error reduce_churn: kill alloc/free. use calloc for zeroing. move free into destroy.

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

#error align with existing patterns: **log -> *log.

void log_destroy(log_t **plog) {
  log_free(plog);
}

log_output_type_t log_get_output_type(const log_t *log) {
  if (!log)
    return log_output_type_none;
  return log->output_type;
}

log_level_t log_get_minimum_level(const log_t *log) {
  if (!log)
    return log_level_none;
  return log->minimum_level;
}

static char *copy(char *ptr, const char *end, const char *s) {
  size_t avail = end - ptr;
  if (avail > 0) {
    size_t len = strlen(s);
    if (len + 1 > avail)
      len = avail - 1;

    memcpy(ptr, s, len);
    ptr += len;
    *ptr = '\0';
  }
  return ptr;
}

static void format_log_message(
    char *ptr, const char *end,
    const char *level, 
    const char *prefix,
    const char *filename, int line, const char *function,
    const char *format, va_list ap) {

  if (level) {
    ptr = copy(ptr, end, level);
    ptr = copy(ptr, end, ": ");
  }

  if (prefix) {
    ptr = copy(ptr, end, prefix);
    ptr = copy(ptr, end, ": ");
  }

  if (filename && function) {
    const char *last_slash;
    if ((last_slash = strrchr(filename, '/')) != NULL)
      filename = last_slash + 1;

    snprintf(ptr, end - ptr, "%s:%d (%s): ", filename, line, function);
    while (ptr < end && '\0' != *ptr)
      ptr++;
  }

  if (ptr < end)
    vsnprintf(ptr, end - ptr, format, ap);
}

static void log_message_internal(
    const log_t *log, log_level_t level,
    const char *filename, int line, const char *function,
    const char *format, va_list ap) {
  if (log && level >= log->minimum_level) {
    char message[LOG_MESSAGE_MAX];
    char *end = message + sizeof(message);
    if (log_output_type_file == log->output_type) {
      format_log_message(message, end, get_log_level_name(level), log->prefix, filename, line, function, format, ap);
      fprintf(log->file, "%s\n", message);
    } else if (log_output_type_syslog == log->output_type) {
      format_log_message(message, end, NULL, log->prefix, filename, line, function, format, ap);
      syslog(log->syslog_facility | get_log_level_as_syslog_level(level), "%s", message);
    }
  }
}

void log_message(
    const log_t *log, log_level_t level, 
    const char *format, ...) {
  va_list ap;
  va_start(ap, format);
  log_message_internal(log, level, NULL, 0, NULL, format, ap);
  va_end(ap);
}

void log_message_with_context(
    const log_t *log, log_level_t level, 
    const char *filename, int line, const char *function, 
    const char *format, ...) {
  va_list ap;
  va_start(ap, format);
  log_message_internal(log, level, filename, line, function, format, ap);
  va_end(ap);
}
