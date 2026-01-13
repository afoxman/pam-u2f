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

#include <assert.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include "log.h"

#define assert_ok(expr) assert(0 == (expr))
#define assert_null(expr) assert(NULL == (expr))

/* Stub to replace syslog() for testing */

FILE *syslog_file = NULL;

ATTRIBUTE_FORMAT(printf, 2, 3)
void syslog(int priority, const char *format, ...) {
  va_list ap;
  fprintf(syslog_file, "priority=%d ", priority);
  va_start(ap, format);
  vfprintf(syslog_file, format, ap);
  fprintf(syslog_file, "\n");
  va_end(ap);
}

static FILE *open_tmp_file(const char *name) {
  char template[256];
  snprintf(template, sizeof(template), "%sXXXXXX", name);

  int fd = mkstemp(template);
  assert(fd != -1 && "Failed to open temp file (mkstemp)");
  FILE *file = fdopen(fd, "r+");
  assert(NULL != file && "Failed to wrap temp file in a FILE* handle");

  // Remove the file so no one can access it. Storage is freed on close.
  // Storage will be released when the file is closed.
  assert(0 == unlink(template));

  return file;
}

static bool first_line_contains(FILE *file, const char *s) {
  char buffer[2500];
  assert_ok(fseek(file, 0, SEEK_SET));
  if (!fgets(buffer, sizeof(buffer), file))
    buffer[0] = '\0';
  return NULL != strstr(buffer, s);
}

static bool file_is_empty(FILE *file) {
  return 0 == ftell(file);
}

static log_t *open_log(log_level_t min, const char *prefix, FILE *file) {
  log_t *log = log_create_file(min, prefix, file);
  assert(NULL != log);
  return log;
}

static log_t *open_syslog(log_level_t min, const char *prefix) {
  log_t *log = log_create_syslog(min, prefix, LOG_USER);
  assert(NULL != log);
  return log;
}

#define LOG_PREFIX         "confabulator"
#define LOG_MESSAGE        "the flim flam is type 17 as expected"
#define LOG_CTX_FILENAME   "confab.c"
#define LOG_CTX_LINE       85
#define LOG_CTX_LINE_STR   "85"
#define LOG_CTX_FUNCTION   "verify_flim_flam"

static void assert_log_contains(const char *caller, const char *s)
{
  FILE *file = open_tmp_file(caller);
  log_t *log = open_log(log_level_info, LOG_PREFIX, file);
  log_message(log, log_level_info, LOG_MESSAGE);
  log_free(log);
  assert(first_line_contains(file, s));
  assert_ok(fclose(file));
}

static void assert_log_ctx_contains(const char *caller, const char *s)
{
  FILE *file = open_tmp_file(caller);
  log_t *log = open_log(log_level_info, LOG_PREFIX, file);
  log_message_ctx(log, log_level_info, LOG_CTX_FILENAME, LOG_CTX_LINE,
    LOG_CTX_FUNCTION, LOG_MESSAGE);
  log_free(log);
  assert(first_line_contains(file, s));
  assert_ok(fclose(file));
}

static void assert_syslog_contains(const char *caller, const char *s)
{
  syslog_file = open_tmp_file(caller);
  log_t *log = open_syslog(log_level_info, LOG_PREFIX);
  log_message(log, log_level_info, LOG_MESSAGE);
  log_free(log);
  assert(first_line_contains(syslog_file, s));
  assert_ok(fclose(syslog_file));
  syslog_file = NULL;
}

static void assert_syslog_ctx_contains(const char *caller, const char *s)
{
  syslog_file = open_tmp_file(caller);
  log_t *log = open_syslog(log_level_info, LOG_PREFIX);
  log_message_ctx(log, log_level_info, LOG_CTX_FILENAME, LOG_CTX_LINE,
    LOG_CTX_FUNCTION, LOG_MESSAGE);
  log_free(log);
  assert(first_line_contains(syslog_file, s));
  assert_ok(fclose(syslog_file));
  syslog_file = NULL;
}

/* 
 * Test Cases
 */

static void test_log_create_file_fails_with_log_level_none(void) {
  assert_null(log_create_file(log_level_none, "prefix", stdout));
}

static void test_log_create_file_fails_with_invalid_log_level(void) {
  assert_null(log_create_file((log_level_t)12345, "prefix", stdout));
}

static void test_log_create_file_fails_with_NULL_file(void) {
  assert_null(log_create_file(log_level_info, "prefix", NULL));
}

static void test_log_create_file_opens_a_file_backed_log(void) {
  log_t *log = open_log(log_level_info, "prefix", stdout);
  assert(log_output_type_file == log_get_output_type(log));
  log_free(log);
}

static void test_log_create_syslog_fails_with_log_level_none(void) {
  assert_null(log_create_syslog(log_level_none, "prefix", LOG_AUTH));
}

static void test_log_create_syslog_fails_with_invalid_log_level(void) {
  assert_null(log_create_syslog((log_level_t)12345, "prefix", LOG_AUTH));
}

static void test_log_create_syslog_opens_a_syslog_backed_log(void) {
  log_t *log = open_syslog(log_level_info, "prefix");
  assert(log_output_type_syslog == log_get_output_type(log));
  log_free(log);
}

static void test_log_get_output_type_returns_none_for_NULL_log(void) {
  assert(log_output_type_none == log_get_output_type(NULL));
}

static void test_log_get_minimum_level_returns_none_for_NULL_log(void) {
  assert(log_level_none == log_get_minimum_level(NULL));
}

static void test_log_get_minimum_level_returns_expected_level(void) {
  log_t *log = open_log(log_level_warn, "prefix", stdout);
  assert(log_level_warn == log_get_minimum_level(log));
  log_free(log);
}

static void test_log_message_writes_prefix(void) {
  assert_log_contains(__func__, LOG_PREFIX);
}

static void test_log_message_writes_level(void) {
  assert_log_contains(__func__, "INFO");
}

static void test_log_message_writes_message(void) {
  assert_log_contains(__func__, LOG_MESSAGE);
}

static void test_log_message_ctx_writes_prefix(void) {
  assert_log_ctx_contains(__func__, LOG_PREFIX);
}

static void test_log_message_ctx_writes_level(void) {
  assert_log_ctx_contains(__func__, "INFO");
}

static void test_log_message_ctx_writes_filename(void) {
  assert_log_ctx_contains(__func__, LOG_CTX_FILENAME);
}

static void test_log_message_ctx_writes_line(void) {
  assert_log_ctx_contains(__func__, LOG_CTX_LINE_STR);
}

static void test_log_message_ctx_writes_function(void) {
  assert_log_ctx_contains(__func__, LOG_CTX_FUNCTION);
}

static void test_log_message_ctx_writes_message(void) {
  assert_log_ctx_contains(__func__, LOG_MESSAGE);
}

static void test_syslog_message_writes_prefix(void) {
  assert_syslog_contains(__func__, LOG_PREFIX);
}

static void test_syslog_message_does_not_write_level(void) {
  syslog_file = open_tmp_file(__func__);
  log_t *log = open_syslog(log_level_info, LOG_PREFIX);
  log_message(log, log_level_info, LOG_MESSAGE);
  log_free(log);
  assert(!first_line_contains(syslog_file, "INFO"));
  assert_ok(fclose(syslog_file));
  syslog_file = NULL;
}

static void test_syslog_message_writes_message(void) {
  assert_syslog_contains(__func__, LOG_MESSAGE);
}

static void test_syslog_message_ctx_writes_prefix(void) {
  assert_syslog_ctx_contains(__func__, LOG_PREFIX);
}

static void test_syslog_message_ctx_does_not_write_level(void) {
  syslog_file = open_tmp_file(__func__);
  log_t *log = open_syslog(log_level_info, LOG_PREFIX);
  log_message_ctx(log, log_level_info, LOG_CTX_FILENAME, LOG_CTX_LINE,
    LOG_CTX_FUNCTION, LOG_MESSAGE);
  log_free(log);
  assert(!first_line_contains(syslog_file, "INFO"));
  assert_ok(fclose(syslog_file));
  syslog_file = NULL;
}

static void test_syslog_message_ctx_writes_filename(void) {
  assert_syslog_ctx_contains(__func__, LOG_CTX_FILENAME);
}

static void test_syslog_message_ctx_writes_line(void) {
  assert_syslog_ctx_contains(__func__, LOG_CTX_LINE_STR);
}

static void test_syslog_message_ctx_writes_function(void) {
  assert_syslog_ctx_contains(__func__, LOG_CTX_FUNCTION);
}

static void test_syslog_message_ctx_writes_message(void) {
  assert_syslog_ctx_contains(__func__, LOG_MESSAGE);
}

static void test_log_message_succeeds_NULL_prefix(void) {
  FILE *file = open_tmp_file(__func__);
  log_t *log = open_log(log_level_info, NULL, file);
  log_message(log, log_level_info, LOG_MESSAGE);
  log_free(log);
  assert(!file_is_empty(file));
  assert_ok(fclose(file));
}

static void test_log_message_ctx_succeeds_NULL_file(void) {
  FILE *file = open_tmp_file(__func__);
  log_t *log = open_log(log_level_info, NULL, file);
  log_message_ctx(log, log_level_info, NULL, LOG_CTX_LINE, LOG_CTX_FUNCTION, 
    LOG_MESSAGE);
  log_free(log);
  assert(!file_is_empty(file));
  assert_ok(fclose(file));
}

static void test_log_message_ctx_succeeds_NULL_func(void) {
  FILE *file = open_tmp_file(__func__);
  log_t *log = open_log(log_level_info, NULL, file);
  log_message_ctx(log, log_level_info, LOG_CTX_FILENAME, LOG_CTX_LINE, NULL,
    LOG_MESSAGE);
  log_free(log);
  assert(!file_is_empty(file));
  assert_ok(fclose(file));
}

static void test_log_message_succeeds_on_NULL_log(void) {
  log_message(NULL, log_level_info, LOG_MESSAGE);
}

static void test_log_message_writes_nothing_on_invalid_level(void) {
  FILE *file = open_tmp_file(__func__);
  log_t *log = open_log(log_level_info, LOG_PREFIX, file);
  log_message(log, (log_level_t)9876, LOG_MESSAGE);
  log_free(log);
  assert(file_is_empty(file));
  assert_ok(fclose(file));
}

static void test_log_message_writes_nothing_when_level_is_too_low(void) {
  FILE *file = open_tmp_file(__func__);
  log_t *log = open_log(log_level_info, LOG_PREFIX, file);
  log_message(log, log_level_trace, LOG_MESSAGE);
  log_free(log);
  assert(file_is_empty(file));
  assert_ok(fclose(file));
}

static void test_log_trace_writes_trace_event_to_file(void) {
  FILE *file = open_tmp_file(__func__);
  log_t *log = open_log(log_level_trace, LOG_PREFIX, file);
  log_trace(log, LOG_MESSAGE);
  log_free(log);
  assert(first_line_contains(file, LOG_MESSAGE));
  assert_ok(fclose(file));
}

static void test_log_info_writes_info_event_to_file(void) {
  FILE *file = open_tmp_file(__func__);
  log_t *log = open_log(log_level_trace, LOG_PREFIX, file);
  log_info(log, LOG_MESSAGE);
  log_free(log);
  assert(first_line_contains(file, LOG_MESSAGE));
  assert_ok(fclose(file));
}

static void test_log_warn_writes_warning_event_to_file(void) {
  FILE *file = open_tmp_file(__func__);
  log_t *log = open_log(log_level_trace, LOG_PREFIX, file);
  log_warn(log, LOG_MESSAGE);
  log_free(log);
  assert(first_line_contains(file, LOG_MESSAGE));
  assert_ok(fclose(file));
}

static void test_log_error_writes_error_event_to_file(void) {
  FILE *file = open_tmp_file(__func__);
  log_t *log = open_log(log_level_trace, LOG_PREFIX, file);
  log_error(log, LOG_MESSAGE);
  log_free(log);
  assert(first_line_contains(file, LOG_MESSAGE));
  assert_ok(fclose(file));
}

static void test_log_trace_writes_trace_event_to_syslog(void) {
  syslog_file = open_tmp_file(__func__);
  log_t *log = open_syslog(log_level_trace, LOG_PREFIX);
  log_trace(log, LOG_MESSAGE);
  log_free(log);
  assert(first_line_contains(syslog_file, LOG_MESSAGE));
  assert_ok(fclose(syslog_file));
  syslog_file = NULL;
}

static void test_log_info_writes_info_event_to_syslog(void) {
  syslog_file = open_tmp_file(__func__);
  log_t *log = open_syslog(log_level_trace, LOG_PREFIX);
  log_info(log, LOG_MESSAGE);
  log_free(log);
  assert(first_line_contains(syslog_file, LOG_MESSAGE));
  assert_ok(fclose(syslog_file));
  syslog_file = NULL;
}

static void test_log_warn_writes_warning_event_to_syslog(void) {
  syslog_file = open_tmp_file(__func__);
  log_t *log = open_syslog(log_level_trace, LOG_PREFIX);
  log_warn(log, LOG_MESSAGE);
  log_free(log);
  assert(first_line_contains(syslog_file, LOG_MESSAGE));
  assert_ok(fclose(syslog_file));
  syslog_file = NULL;
}

static void test_log_error_writes_error_event_to_syslog(void) {
  syslog_file = open_tmp_file(__func__);
  log_t *log = open_syslog(log_level_trace, LOG_PREFIX);
  log_error(log, LOG_MESSAGE);
  log_free(log);
  assert(first_line_contains(syslog_file, LOG_MESSAGE));
  assert_ok(fclose(syslog_file));
  syslog_file = NULL;
}

int main(void) {
  test_log_create_file_fails_with_log_level_none();
  test_log_create_file_fails_with_invalid_log_level();
  test_log_create_file_fails_with_NULL_file();
  test_log_create_file_opens_a_file_backed_log();
  test_log_create_syslog_fails_with_log_level_none();
  test_log_create_syslog_fails_with_invalid_log_level();
  test_log_create_syslog_opens_a_syslog_backed_log();
  test_log_get_output_type_returns_none_for_NULL_log();
  test_log_get_minimum_level_returns_none_for_NULL_log();
  test_log_get_minimum_level_returns_expected_level();
  test_log_message_writes_prefix();
  test_log_message_writes_level();
  test_log_message_writes_message();
  test_log_message_ctx_writes_prefix();
  test_log_message_ctx_writes_level();
  test_log_message_ctx_writes_filename();
  test_log_message_ctx_writes_line();
  test_log_message_ctx_writes_function();
  test_log_message_ctx_writes_message();
  test_syslog_message_writes_prefix();
  test_syslog_message_does_not_write_level();
  test_syslog_message_writes_message();
  test_syslog_message_ctx_writes_prefix();
  test_syslog_message_ctx_does_not_write_level();
  test_syslog_message_ctx_writes_filename();
  test_syslog_message_ctx_writes_line();
  test_syslog_message_ctx_writes_function();
  test_syslog_message_ctx_writes_message();
  test_log_message_succeeds_NULL_prefix();
  test_log_message_ctx_succeeds_NULL_file();
  test_log_message_ctx_succeeds_NULL_func();
  test_log_message_succeeds_on_NULL_log();
  test_log_message_writes_nothing_on_invalid_level();
  test_log_message_writes_nothing_when_level_is_too_low();
  test_log_trace_writes_trace_event_to_file();
  test_log_info_writes_info_event_to_file();
  test_log_warn_writes_warning_event_to_file();
  test_log_error_writes_error_event_to_file();
  test_log_trace_writes_trace_event_to_syslog();
  test_log_info_writes_info_event_to_syslog();
  test_log_warn_writes_warning_event_to_syslog();
  test_log_error_writes_error_event_to_syslog();
  return 0;
}
