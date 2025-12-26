/*
 *  Copyright (C) 2025 Yubico AB - See COPYING
 */

#undef NDEBUG
#define DEBUG_PAM // Enable file/line/function data in log messages

#include <assert.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>
#include <sys/stat.h>

#include "log.h"

#define assert_var_ex(type, name, expr, bad)  type name = expr; assert(name != bad)
#define assert_var(type, var, expr)           assert_var_ex(type, var, expr, NULL)
#define assert_ok(expr)                       assert(0 == (expr))

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

  assert_var_ex(int, fd, mkstemp(template), -1);
  assert_var(FILE*, file, fdopen(fd, "w+"));

  // Try to remove file now. It will stay open, but will not be accessible through the filesystem.
  // Space will be freed when the file is closed.
  unlink(template);

  return file;
}

static void rewind_file(FILE *file) {
  assert_ok(fflush(file));
  assert_ok(fseek(file, 0, SEEK_SET));
}

static bool next_line_contains(FILE *file, const char *s) {
  char buffer[2500];
  if (!fgets(buffer, sizeof(buffer), file))
    buffer[0] = '\0';
  return NULL != strstr(buffer, s);
}

static bool file_is_empty(FILE *file) {
  struct stat st;
  assert_ok(fstat(fileno(file), &st));
  return st.st_size == 0;
}

static void test_file_trace_is_logged(void) {
  const char *message = "This is a test trace message";
  assert_var(FILE*, file, open_tmp_file(__func__));
  assert_var(log_t*, log, log_create_using_file(log_level_trace, __func__, file));
  log_trace(log, "%s", message);
  log_destroy(&log);
  rewind_file(file);
  assert(next_line_contains(file, message));
  assert_ok(fclose(file));
}

static void test_file_warn_is_logged(void) {
  const char *message = "This is a test warning message";
  assert_var(FILE*, file, open_tmp_file(__func__));
  assert_var(log_t*, log, log_create_using_file(log_level_trace, __func__, file));
  log_warn(log, "%s", message);
  log_destroy(&log);
  rewind_file(file);
  assert(next_line_contains(file, message));
  assert_ok(fclose(file));
}

static void test_file_info_is_skipped(void) {
  const char *message = "This info message should not be logged";
  assert_var(FILE*, file, open_tmp_file(__func__));
  assert_var(log_t*, log, log_create_using_file(log_level_warn, __func__, file));
  log_info(log, "%s", message);
  log_destroy(&log);
  assert(file_is_empty(file));
  assert_ok(fclose(file));
}

static void test_syslog_info_is_logged(void) {
  const char *message = "This info message should be sent to syslog";
  assert_var(FILE*, file, open_tmp_file(__func__));
  syslog_file = file;
  assert_var(log_t*, log, log_create_using_syslog(log_level_trace, __func__, LOG_USER));
  log_info(log, "%s", message);
  log_destroy(&log);
  rewind_file(file);
  assert(next_line_contains(file, message));
  assert_ok(fclose(file));
  syslog_file = NULL;
}

static void test_syslog_trace_is_skipped(void) {
  const char *message = "This trace message should NOT be sent to syslog";
  assert_var(FILE*, file, open_tmp_file(__func__));
  syslog_file = file;
  assert_var(log_t*, log, log_create_using_syslog(log_level_info, __func__, LOG_USER));
  log_trace(log, "%s", message);
  log_destroy(&log);
  rewind_file(file);
  assert(file_is_empty(file));
  assert_ok(fclose(file));
  syslog_file = NULL;
}

static void test_file_message_contains_prefix(void) {
  const char *prefix = "test-log-prefix";
  const char *message = "This is a test message";
  assert_var(FILE*, file, open_tmp_file(__func__));
  assert_var(log_t*, log, log_create_using_file(log_level_trace, prefix, file));
  log_info(log, "%s", message);
  log_destroy(&log);
  rewind_file(file);
  assert(next_line_contains(file, prefix));
  assert_ok(fclose(file));
}

#ifdef DEBUG_PAM

static void test_file_message_contains_source_file(void) {
  const char *message = "This is a test message";
  assert_var(FILE*, file, open_tmp_file(__func__));
  assert_var(log_t*, log, log_create_using_file(log_level_trace, __func__, file));
  log_info(log, "%s", message);
  log_destroy(&log);
  rewind_file(file);
  assert(next_line_contains(file, __FILE__));
  assert_ok(fclose(file));
}

static void test_file_message_contains_source_function(void) {
  const char *message = "This is a test message";
  assert_var(FILE*, file, open_tmp_file(__func__));
  assert_var(log_t*, log, log_create_using_file(log_level_trace, __func__, file));
  log_info(log, "%s", message);
  log_destroy(&log);
  rewind_file(file);
  assert(next_line_contains(file, __func__));
  assert_ok(fclose(file));
}

#endif // DEBUG_PAM

static void test_file_message_contains_log_level_name(void) {
  const char *message = "This is a test message";
  assert_var(FILE*, file, open_tmp_file(__func__));
  assert_var(log_t*, log, log_create_using_file(log_level_trace, __func__, file));
  log_info(log, "%s", message);
  log_destroy(&log);
  rewind_file(file);
  assert(next_line_contains(file, "INFO:"));
  assert_ok(fclose(file));
}

int main(void) {
  test_file_trace_is_logged();
  test_file_warn_is_logged();
  test_file_info_is_skipped();

  test_syslog_info_is_logged();
  test_syslog_trace_is_skipped();

#ifdef DEBUG_PAM
  test_file_message_contains_prefix();
  test_file_message_contains_source_file();
  test_file_message_contains_source_function();
#endif // DEBUG_PAM
  test_file_message_contains_log_level_name();

  return 0;
}
