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

#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>

#include "log.h"

#define LOG_MESSAGE_MAX 2000

typedef struct {
  const char *name;
  const int syslog_priority;
} log_level_info_t;

static const log_level_info_t level_info[log_level_error + 1] = {
  { .name = NULL, .syslog_priority = 0 },
  { .name = "TRACE", .syslog_priority = LOG_DEBUG },
  { .name = "INFO", .syslog_priority = LOG_INFO },
  { .name = "WARNING", .syslog_priority = LOG_WARNING },
  { .name = "ERROR", .syslog_priority = LOG_ERR }
};

struct log {
  log_output_type_t output_type;
  FILE *file;
  int syslog_facility;

  log_level_t minimum_level;

  const char *prefix;
};

log_t *log_create_file(log_level_t min, const char *prefix, FILE *file) {
  if (min < log_level_trace || min > log_level_error || !file)
    return NULL;

  log_t *log = calloc(1, sizeof(log_t));
  if (log) {
    log->output_type = log_output_type_file;
    log->file = file;
    log->minimum_level = min;
    log->prefix = prefix ? strdup(prefix) : NULL;
  }
  return log;
}

log_t *log_create_syslog(log_level_t min, const char *prefix, int facility) {
  if (min < log_level_trace || min > log_level_error)
    return NULL;

  log_t *log = calloc(1, sizeof(log_t));
  if (log) {
    log->output_type = log_output_type_syslog;
    log->syslog_facility = facility & LOG_FACMASK;
    log->minimum_level = min;
    log->prefix = prefix ? strdup(prefix) : NULL;
  }
  return log;
}

void log_free(log_t *log) {
  if (log) {
    free((char*)log->prefix);
    free(log);
  }
}

log_output_type_t log_get_output_type(const log_t *log) {
  return log ? log->output_type : log_output_type_none;
}

log_level_t log_get_minimum_level(const log_t *log) {
  return log ? log->minimum_level : log_level_none;
}

static char *copy(char *ptr, const char *end, const char *s) {
  size_t avail = end - ptr;
  if (avail > 0) {
    size_t len = strlen(s);
    if (len + 1 > avail)
      len = avail - 1;

    ptr = (char*)memcpy(ptr, s, len) + len;
    *ptr = '\0';
  }
  return ptr;
}

static void format(char *ptr, size_t len, const char *level, 
  const char *prefix, const char *file, int line, const char *func,
  const char *fmt, va_list ap) 
{
  char *end = ptr + len;
  if (level) {
    ptr = copy(ptr, end, level);
    ptr = copy(ptr, end, ": ");
  }
  if (prefix) {
    ptr = copy(ptr, end, prefix);
    ptr = copy(ptr, end, ": ");
  }
  if (file && func) {
    const char *last_slash;
    if ((last_slash = strrchr(file, '/')) != NULL)
      file = last_slash + 1;
    snprintf(ptr, end - ptr, "%s:%d (%s): ", file, line, func);
    while (ptr < end && '\0' != *ptr)
      ptr++;
  }
  if (ptr < end)
    vsnprintf(ptr, end - ptr, fmt, ap);
}

static void log_write(const log_t *log, log_level_t level, const char *file, 
  int line, const char *func, const char *fmt, va_list ap)
{
  if (log && level >= log->minimum_level && level <= log_level_error) {
    const log_level_info_t *info = &level_info[level];
    char msg[LOG_MESSAGE_MAX];
    if (log_output_type_file == log->output_type) {
      format(msg, sizeof(msg), info->name, log->prefix, file, line, func, fmt, ap);
      fputs(msg, log->file);
      fputc('\n', log->file);
    } else if (log_output_type_syslog == log->output_type) {
      format(msg, sizeof(msg), NULL, log->prefix, file, line, func, fmt, ap);
      syslog(log->syslog_facility | info->syslog_priority, "%s", msg);
    }
  }
}

void log_message(const log_t *log, log_level_t level, const char *fmt, ...) 
{
  va_list ap;
  va_start(ap, fmt);
  log_write(log, level, NULL, 0, NULL, fmt, ap);
  va_end(ap);
}

void log_message_ctx(const log_t *log, log_level_t level, const char *file, 
  int line, const char *func, const char *fmt, ...)
{
  va_list ap;
  va_start(ap, fmt);
  log_write(log, level, file, line, func, fmt, ap);
  va_end(ap);
}
