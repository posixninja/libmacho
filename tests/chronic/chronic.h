/**
 * tests/chronic/chronic.h - Stub replacement for libchronic.
 * Provides the debug macros and the file_read() helper used by the
 * library sources so that the test suite can compile without an
 * installed libchronic.
 */
#ifndef CHRONIC_H_
#define CHRONIC_H_

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "debug.h"

/* Stub for chronic's file_read() helper. */
static inline int file_read(const char *path, unsigned char **data,
                             unsigned int *size)
{
    FILE *fp;
    long len;

    if (!path || !data || !size)
        return -1;

    fp = fopen(path, "rb");
    if (!fp)
        return -1;

    if (fseek(fp, 0, SEEK_END) != 0) {
        fclose(fp);
        return -1;
    }
    len = ftell(fp);
    if (len < 0) {
        fclose(fp);
        return -1;
    }
    rewind(fp);

    *data = malloc((size_t)len);
    if (!*data) {
        fclose(fp);
        return -1;
    }
    if ((unsigned long)len > (unsigned long)(unsigned int)-1) {
        free(*data);
        *data = NULL;
        fclose(fp);
        return -1;
    }
    *size = (unsigned int)len;
    if (fread(*data, 1, (size_t)len, fp) != (size_t)len) {
        free(*data);
        *data = NULL;
        fclose(fp);
        return -1;
    }
    fclose(fp);
    return 0;
}

#endif /* CHRONIC_H_ */
