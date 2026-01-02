/*
 * Copyright (C) 2021 Yubico AB - See COPYING
 */

#ifndef DEFS_H
#define DEFS_H

#ifdef __GNUC__
#define ATTRIBUTE_FORMAT(f, s, a) __attribute__((format(f, s, a)))
#else
#define ATTRIBUTE_FORMAT(f, s, a)
#endif

#endif /* DEFS_H */
