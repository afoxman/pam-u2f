/*
 * Copyright (C) 2021 Yubico AB - See COPYING
 */

#ifndef DEBUG_H
#define DEBUG_H

#include <stdio.h>

#define DEFAULT_DEBUG_FILE stderr

typedef struct {
  int enabled;
  FILE *file;
  int simple;
} debug_log_t;

#if defined(DEBUG_PAM)
#define log_msg(log, ...)  debug_printf(log, __FILE__, __LINE__, __func__, __VA_ARGS__)
#else /* !DEBUG_PAM */
#define log_msg(log, ...)  debug_printf(log, NULL, 0, NULL, __VA_ARGS__)
#endif /* DEBUG_PAM */

#ifdef __GNUC__
#define ATTRIBUTE_FORMAT(f, s, a) __attribute__((format(f, s, a)))
#else
#define ATTRIBUTE_FORMAT(f, s, a)
#endif

FILE *debug_open(const char *);
void debug_close(FILE *f);
void debug_printf(debug_log_t *, const char *, int, const char *, const char *, ...)
  ATTRIBUTE_FORMAT(printf, 5, 6);

#endif /* DEBUG_H */
