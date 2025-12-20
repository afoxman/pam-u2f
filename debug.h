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
#define D(file, simple, ...)                                                   \
  debug_fprintf(file, simple, __FILE__, __LINE__, __func__, __VA_ARGS__)
#else
#define D(file, ...) ((void) 0)
#endif /* DEBUG_PAM */

#define debug_dbg(l, ...)                                                      \
  do {                                                                         \
    if (l->enabled) {                                                          \
      D(l->file, l->simple, __VA_ARGS__);                                      \
    }                                                                          \
  } while (0)

#ifdef __GNUC__
#define ATTRIBUTE_FORMAT(f, s, a) __attribute__((format(f, s, a)))
#else
#define ATTRIBUTE_FORMAT(f, s, a)
#endif

FILE *debug_open(const char *);
void debug_close(FILE *f);
void debug_fprintf(FILE *, int, const char *, int, const char *, const char *, ...)
  ATTRIBUTE_FORMAT(printf, 6, 7);

#endif /* DEBUG_H */
