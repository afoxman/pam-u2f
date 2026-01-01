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
  log_level_none = 0,
  log_level_trace = 1,
  log_level_info = 2,
  log_level_warn = 3,
  log_level_error = 4
} log_level_t;

typedef struct log log_t;

log_t *log_create_file(log_level_t min, const char *prefix, FILE *file);
log_t *log_create_syslog(log_level_t min, const char *prefix, int facility);
void log_free(log_t *log);

log_output_type_t log_get_output_type(const log_t *log);
log_level_t log_get_minimum_level(const log_t *log);

void log_message(const log_t *log, log_level_t level, const char *fmt, ...)
  ATTRIBUTE_FORMAT(printf, 3, 4);

void log_message_ctx(const log_t *log, log_level_t level, const char *file, 
  int line, const char *func, const char *fmt, ...)
  ATTRIBUTE_FORMAT(printf, 6, 7);

#ifdef LOG_INCLUDE_CONTEXT

#define log_trace(log, ...) log_message_ctx(log, log_level_trace, \
  __FILE__, __LINE__, __func__, __VA_ARGS__)
#define log_info(log, ...)  log_message_ctx(log, log_level_info, \
  __FILE__, __LINE__, __func__, __VA_ARGS__)
#define log_warn(log, ...)  log_message_ctx(log, log_level_warn, \
  __FILE__, __LINE__, __func__, __VA_ARGS__)
#define log_error(log, ...) log_message_ctx(log, log_level_error, \
  __FILE__, __LINE__, __func__, __VA_ARGS__)

#else // !LOG_INCLUDE_CONTEXT

#define log_trace(log, ...) log_message(log, log_level_trace, __VA_ARGS__)
#define log_info(log, ...)  log_message(log, log_level_info, __VA_ARGS__)
#define log_warn(log, ...)  log_message(log, log_level_warn, __VA_ARGS__)
#define log_error(log, ...) log_message(log, log_level_error, __VA_ARGS__)

#endif // LOG_INCLUDE_CONTEXT

#endif // LOG_H
