/*
 * Copyright (C) 2025 Yubico AB - See COPYING
 */

#ifndef LOG_H
#define LOG_H

#include <stdbool.h>
#include <stdio.h>

#include "defs.h"

typedef enum log_output_type {
  log_output_type_none,
  log_output_type_file,
  log_output_type_syslog
} log_output_type_t;

typedef enum log_level {
  log_level_none,
  log_level_trace,
  log_level_info,
  log_level_warn,
  log_level_error
} log_level_t;

typedef struct log log_t;

log_t *log_create_using_file(log_level_t minimum_level, const char *prefix, FILE *file);
log_t *log_create_using_syslog(log_level_t minimum_level, const char *prefix, int facility);
void log_destroy(log_t **plog);

log_output_type_t log_get_output_type(const log_t *log);
log_level_t log_get_minimum_level(const log_t *log);

void log_message(
    const log_t *log,
    const char *filename, int line, const char *function, 
    log_level_t level,
    const char *format, ...) 
    ATTRIBUTE_FORMAT(printf, 6, 7);

#if defined(DEBUG_PAM)
#define __log_message(log, level, format, ...) log_message(log, __FILE__, __LINE__, __func__, level, format, ##__VA_ARGS__)
#else /* !DEBUG_PAM */
#define __log_message(log, level, format, ...) log_message(log, NULL, 0, NULL, level, format, ##__VA_ARGS__)
#endif /* DEBUG_PAM */

#define log_error(log, format, ...)  __log_message(log, log_level_error, format, ##__VA_ARGS__)
#define log_warn(log, format, ...)   __log_message(log, log_level_warn, format, ##__VA_ARGS__)
#define log_info(log, format, ...)   __log_message(log, log_level_info, format, ##__VA_ARGS__)
#define log_trace(log, format, ...)  __log_message(log, log_level_trace, format, ##__VA_ARGS__)

#endif // LOG_H
