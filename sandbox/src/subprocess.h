/* Secure subprocess execution — Windows API (CreateProcess + pipes).
 *
 * NEVER uses system() or popen() — those go through cmd.exe
 * and are vulnerable to command injection. CreateProcess runs the
 * binary directly with no shell interpretation.
 */
#ifndef SUBPROCESS_H
#define SUBPROCESS_H

#include <stddef.h>

/* Run a command with arguments, capture stdout and stderr.
 *
 * cmd:   full path to executable
 * argv:  NULL-terminated argument list (argv[0] is the program name)
 * timeout_sec:  maximum seconds to wait (0 = no timeout)
 * exit_code:    [out] process exit code
 * stdout_buf:   [out] captured stdout (caller-allocated)
 * stdout_size:  size of stdout_buf in bytes
 * stderr_buf:   [out] captured stderr (caller-allocated)
 * stderr_size:  size of stderr_buf in bytes
 *
 * Returns 0 on success, -1 on spawn failure, -2 on timeout.
 */
int subprocess_run(
    const char *cmd,
    char *const argv[],
    int timeout_sec,
    int *exit_code,
    char *stdout_buf,
    size_t stdout_size,
    char *stderr_buf,
    size_t stderr_size
);

/* Check if a command exists on PATH. Returns 1 if found, 0 if not. */
int subprocess_which(const char *cmd);

#endif /* SUBPROCESS_H */
