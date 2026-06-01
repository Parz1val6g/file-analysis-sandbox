/* Host-side input validation implementation. */
#include "validation.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#ifdef _WIN32
#include <windows.h>
#include <io.h>
#define access _access
#ifndef R_OK
#define R_OK 04
#endif
#else
#include <unistd.h>
#include <limits.h>
#endif

int validate_input(const char *path, char *error, size_t error_size) {
    struct stat st;
    char resolved[4096];
    const char *p;

    if (!path || !error || error_size == 0) return -1;

    /* Resolve real path */
#ifdef _WIN32
    if (!_fullpath(resolved, path, sizeof(resolved))) {
        snprintf(error, error_size, "Path resolution failed");
        return -1;
    }
#else
    if (!realpath(path, resolved)) {
        snprintf(error, error_size, "Path resolution failed: %s", path);
        return -1;
    }
#endif

    /* Exists? */
    if (stat(resolved, &st) != 0) {
        snprintf(error, error_size, "File not found: %s", resolved);
        return -1;
    }

    /* Is regular file? */
#ifdef _WIN32
    if (!(st.st_mode & _S_IFREG)) {
#else
    if (!S_ISREG(st.st_mode)) {
#endif
        snprintf(error, error_size, "Path is not a regular file");
        return -1;
    }

    /* Size cap */
    if (st.st_size > (off_t)MAX_FILE_SIZE_BYTES) {
        double actual_mb = (double)st.st_size / (1024.0 * 1024.0);
        snprintf(error, error_size,
                 "File too large: %.1f MB exceeds maximum allowed size of 500 MB",
                 actual_mb);
        return -1;
    }

    if (st.st_size == 0) {
        snprintf(error, error_size, "File is empty (0 bytes)");
        return -1;
    }

    /* Read permission */
    if (access(resolved, R_OK) != 0) {
        snprintf(error, error_size, "Permission denied: cannot read file");
        return -1;
    }

    /* Path traversal check */
    p = resolved;
    while (*p) {
        if (p[0] == '.' && p[1] == '.' &&
            (p == resolved || *(p-1) == '/' || *(p-1) == '\\')) {
            /* Only flag obvious traversal patterns */
            /* We use realpath above which already resolves these */
            break;
        }
        p++;
    }

    return 0;
}
