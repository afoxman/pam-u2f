/*
 * Copyright (C) 2025 Yubico AB - See COPYING
 */

#ifndef LOG_H
#define LOG_H

#include <stdbool.h>
#include <stdio.h>

#include "defs.h"

typedef enum log_level {
  log_level_trace = 1,
  log_level_info = 2,
  log_level_warn = 3,
  log_level_error = 4
} log_level_t;

typedef struct log log_t;

log_t *log_create_using_file(log_level_t level, FILE *file);
log_t *log_create_using_syslog(log_level_t level);
void log_destroy(log_t **plog);

void log_message(
    const log_t *log, 
    log_level_t level, 
    const char *filename,
    int line, 
    const char *function, 
    const char *format, 
    ...) 
    ATTRIBUTE_FORMAT(printf, 6, 7);

#if defined(DEBUG_PAM)
#define __log_message(level, format, ...) log_message(level, __FILE__, __LINE__, __func__, format, __VA_ARGS__)
#else /* !DEBUG_PAM */
#define __log_message(level, format, ...) log_message(level, "", 0, "", format, __VA_ARGS__)
#endif /* DEBUG_PAM */

#define log_error(format, ...)  __log_message(log_level_error, format, __VA_ARGS__)
#define log_warn(format, ...)   __log_message(log_level_warn, format, __VA_ARGS__)
#define log_info(format, ...)   __log_message(log_level_info, format, __VA_ARGS__)
#define log_trace(format, ...)  __log_message(log_level_trace, format, __VA_ARGS__)

#endif // LOG_H
