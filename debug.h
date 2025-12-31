/*
 * Copyright (C) 2021 Yubico AB - See COPYING
 */

#ifndef DEBUG_H
#define DEBUG_H

#include <stdio.h>

#include "log.h"

#define DEFAULT_DEBUG_FILE stderr

#define debug_dbg(cfg, ...) log_trace(cfg->log, __VA_ARGS__)

FILE *debug_open(const char *filename);
void debug_close(FILE *f);

#endif /* DEBUG_H */
