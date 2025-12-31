/*
 * Copyright (C) 2021 Yubico AB - See COPYING
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdarg.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include "debug.h"

FILE *debug_open(const char *filename) {
  struct stat st;
  FILE *file;
  int fd;

  if (strcmp(filename, "stdout") == 0)
    return stdout;
  if (strcmp(filename, "stderr") == 0)
    return stderr;
  if (strcmp(filename, "syslog") == 0)
    return NULL;

  fd = open(filename, O_WRONLY | O_APPEND | O_CLOEXEC | O_NOFOLLOW | O_NOCTTY);
  if (fd == -1 || fstat(fd, &st) != 0)
    goto err;

#ifndef WITH_FUZZING
  if (!S_ISREG(st.st_mode))
    goto err;
#endif

  if ((file = fdopen(fd, "a")) != NULL)
    return file;

err:
  if (fd != -1)
    close(fd);

  return DEFAULT_DEBUG_FILE; /* fallback to default */
}

void debug_close(FILE *f) {
  if (f != NULL && f != stdout && f != stderr)
    fclose(f);
}
