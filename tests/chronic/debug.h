/**
 * tests/chronic/debug.h - Stub replacement for libchronic debug macros.
 * Used by the standalone test build so that libchronic is not required.
 */
#ifndef CHRONIC_DEBUG_H_
#define CHRONIC_DEBUG_H_

#include <stdio.h>

/* Suppress debug output during tests; forward errors to stderr. */
#define debug(fmt, ...)  ((void)0)
#define error(fmt, ...)  fprintf(stderr, "ERROR: " fmt, ##__VA_ARGS__)

#endif /* CHRONIC_DEBUG_H_ */
