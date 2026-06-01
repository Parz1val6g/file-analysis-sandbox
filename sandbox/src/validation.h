/* Host-side input validation — size caps, perms, traversal detection. */
#ifndef VALIDATION_H
#define VALIDATION_H

#include <stddef.h>

#define MAX_FILE_SIZE_BYTES  (500ULL * 1024 * 1024)  /* 500 MB */

/* Validate input file. Returns 0 if valid, or fills `error` and returns -1.
 * On success, `resolved_out` (if non-NULL) receives the canonical absolute path.
 * Use resolved_out for all subsequent file operations to avoid TOCTOU races. */
int validate_input(const char *path,
                   char *resolved_out, size_t resolved_size,
                   char *error, size_t error_size);

#endif /* VALIDATION_H */
