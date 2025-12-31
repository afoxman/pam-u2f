/*
 * Copyright (C) 2021 Yubico AB - See COPYING
 */

#ifndef DEBUG_H
#define DEBUG_H

#include <stddef.h>

#include "log.h"

#define debug_dbg(cfg, ...) log_trace(cfg->log, __VA_ARGS__)

FILE *debug_open(const char *filename);
void debug_close(FILE *f);

#endif /* DEBUG_H */
