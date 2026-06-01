/* Secure subprocess execution.
 *
 * Windows: CreateProcessW with explicit argument passing — no shell, no cmd.exe.
 * Linux:   fork/execvp with poll-based pipe draining — no system()/popen().
 * Both implementations are immune to command injection.
 */

#include "subprocess.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <windows.h>

#define MAX_CMDLINE 32768

/* ---- Command-line builder ---- */

static int build_cmdline(char *const argv[], wchar_t *out, size_t out_chars) {
    size_t pos = 0;
    int i;

    out[0] = L'\0';
    for (i = 0; argv[i] != NULL; i++) {
        const char *arg = argv[i];
        int needs_quote = 0;
        const char *p;

        if (i > 0) {
            if (pos + 1 >= out_chars) return -1;
            out[pos++] = L' ';
        }

        for (p = arg; *p; p++) {
            if (*p == ' ' || *p == '\t' || *p == '"') { needs_quote = 1; break; }
        }
        if (arg[0] == '\0') needs_quote = 1;

        if (needs_quote) {
            if (pos + 1 >= out_chars) return -1;
            out[pos++] = L'"';
            for (p = arg; *p; p++) {
                int backslashes = 0;
                while (*p == '\\') { backslashes++; p++; }
                if (*p == '"') {
                    int j;
                    for (j = 0; j < backslashes * 2; j++) {
                        if (pos >= out_chars) return -1;
                        out[pos++] = L'\\';
                    }
                    if (pos >= out_chars) return -1;
                    out[pos++] = L'\\';
                    if (pos >= out_chars) return -1;
                    out[pos++] = L'"';
                } else if (*p == '\0') {
                    int j;
                    for (j = 0; j < backslashes * 2; j++) {
                        if (pos >= out_chars) return -1;
                        out[pos++] = L'\\';
                    }
                    break;
                } else {
                    int j;
                    for (j = 0; j < backslashes; j++) {
                        if (pos >= out_chars) return -1;
                        out[pos++] = L'\\';
                    }
                    if (pos >= out_chars) return -1;
                    out[pos++] = (wchar_t)(unsigned char)*p;
                }
            }
            if (pos >= out_chars) return -1;
            out[pos++] = L'"';
        } else {
            for (p = arg; *p; p++) {
                if (pos >= out_chars) return -1;
                out[pos++] = (wchar_t)(unsigned char)*p;
            }
        }
    }
    if (pos >= out_chars) return -1;
    out[pos] = L'\0';
    return 0;
}

/* ---- Binary discovery (manual PATH search, no side effects) ---- */

int subprocess_which(const char *cmd) {
    /* Search PATH manually — avoids executing the binary like CreateProcess would */
    char path_env[32768];
    char test_path[MAX_PATH];
    const char *exts[] = {".exe", ".com", ".bat", ".cmd", "", NULL};
    DWORD len;
    const char *start, *end;
    int i;

    /* Check current directory first */
    for (i = 0; exts[i]; i++) {
        snprintf(test_path, sizeof(test_path), "%s%s", cmd, exts[i]);
        if (GetFileAttributesA(test_path) != INVALID_FILE_ATTRIBUTES)
            return 1;
    }

    /* Search PATH */
    len = GetEnvironmentVariableA("PATH", path_env, sizeof(path_env));
    if (len == 0 || len >= sizeof(path_env)) return 0;

    start = path_env;
    while (*start) {
        /* Find end of this PATH entry (semicolon-delimited) */
        end = strchr(start, ';');
        if (!end) end = start + strlen(start);

        if (end > start && (size_t)(end - start) + strlen(cmd) + 5 < MAX_PATH) {
            size_t dirlen = (size_t)(end - start);
            memmove(test_path, start, dirlen);
            if (dirlen > 0 && test_path[dirlen - 1] != '\\' && test_path[dirlen - 1] != '/')
                test_path[dirlen++] = '\\';
            memmove(test_path + dirlen, cmd, strlen(cmd) + 1);

            for (i = 0; exts[i]; i++) {
                char full[MAX_PATH];
                snprintf(full, sizeof(full), "%s%s", test_path, exts[i]);
                if (GetFileAttributesA(full) != INVALID_FILE_ATTRIBUTES)
                    return 1;
            }
        }

        start = (*end) ? end + 1 : end;
    }

    return 0;
}

/* ---- Secure process execution ---- */

/* Read available data from a pipe handle */
static DWORD drain_pipe(HANDLE h, char *buf, size_t bufsize, size_t *total) {
    DWORD avail, nread;
    if (!buf || bufsize == 0) return 0;
    if (!PeekNamedPipe(h, NULL, 0, NULL, &avail, NULL) || avail == 0)
        return 0;
    if (*total >= bufsize - 1)
        return 0;
    DWORD space = (DWORD)(bufsize - *total - 1);
    DWORD to_read = (avail < space) ? avail : space;
    if (!ReadFile(h, buf + *total, to_read, &nread, NULL))
        return 0;
    *total += nread;
    if (*total < bufsize)
        buf[*total] = '\0';
    return nread;
}

int subprocess_run(
    const char *cmd,
    char *const argv[],
    int timeout_sec,
    int *exit_code,
    char *stdout_buf,
    size_t stdout_size,
    char *stderr_buf,
    size_t stderr_size
) {
    HANDLE h_stdout_rd = NULL, h_stdout_wr = NULL;
    HANDLE h_stderr_rd = NULL, h_stderr_wr = NULL;
    SECURITY_ATTRIBUTES sa;
    STARTUPINFOW si;
    PROCESS_INFORMATION pi;
    wchar_t wcmd[MAX_CMDLINE / 2];
    DWORD wait_result;
    int ret = -1;
    size_t out_total = 0, err_total = 0;
    DWORD start_tick = 0;
    DWORD timeout_ms  = 0;

    (void)cmd; /* argv[0] is the actual executable; cmd is kept for API compatibility */

    if (!argv) return -1;

    if (stdout_buf && stdout_size > 0) stdout_buf[0] = '\0';
    if (stderr_buf && stderr_size > 0) stderr_buf[0] = '\0';

    memset(&sa, 0, sizeof(sa));
    sa.nLength = sizeof(sa);
    sa.bInheritHandle = TRUE;

    if (!CreatePipe(&h_stdout_rd, &h_stdout_wr, &sa, 0)) goto cleanup;
    if (!SetHandleInformation(h_stdout_rd, HANDLE_FLAG_INHERIT, 0)) goto cleanup;

    if (!CreatePipe(&h_stderr_rd, &h_stderr_wr, &sa, 0)) goto cleanup;
    if (!SetHandleInformation(h_stderr_rd, HANDLE_FLAG_INHERIT, 0)) goto cleanup;

    if (build_cmdline(argv, wcmd, MAX_CMDLINE / 2) != 0) goto cleanup;

    memset(&si, 0, sizeof(si));
    si.cb = sizeof(si);
    si.hStdOutput = h_stdout_wr;
    si.hStdError  = h_stderr_wr;
    si.hStdInput  = GetStdHandle(STD_INPUT_HANDLE);
    si.dwFlags    = STARTF_USESTDHANDLES;

    memset(&pi, 0, sizeof(pi));

    if (!CreateProcessW(NULL, wcmd, NULL, NULL, TRUE, CREATE_NO_WINDOW,
                        NULL, NULL, &si, &pi))
        goto cleanup;

    /* Close our write ends so reads don't block */
    CloseHandle(h_stdout_wr); h_stdout_wr = NULL;
    CloseHandle(h_stderr_wr); h_stderr_wr = NULL;

    /* Record wall-clock start for timeout tracking.
     * GetTickCount() is 32-bit and wraps every ~49 days; unsigned subtraction
     * gives the correct elapsed time even across the wrap boundary. */
    if (timeout_sec > 0) {
        start_tick = GetTickCount();
        timeout_ms  = (DWORD)timeout_sec * 1000U;
    }

    /* Wait loop with concurrent pipe draining (prevents deadlocks) */
    for (;;) {
        DWORD remaining;
        HANDLE handles[3];
        DWORD nhandles = 0;

        /* Compute remaining time against wall-clock start (not reset per iter) */
        if (timeout_sec > 0) {
            DWORD elapsed = GetTickCount() - start_tick; /* safe across wrap */
            if (elapsed >= timeout_ms) {
                TerminateProcess(pi.hProcess, 1);
                ret = -2;
                if (exit_code) *exit_code = -1;
                goto cleanup;
            }
            remaining = timeout_ms - elapsed;
        } else {
            remaining = INFINITE;
        }

        /* Build handle list: always process first, then any live pipe handles */
        handles[nhandles++] = pi.hProcess;
        if (h_stdout_rd) handles[nhandles++] = h_stdout_rd;
        if (h_stderr_rd) handles[nhandles++] = h_stderr_rd;

        wait_result = WaitForMultipleObjects(nhandles, handles, FALSE, remaining);

        /* Drain both pipes concurrently */
        if (stdout_buf && stdout_size > 1)
            drain_pipe(h_stdout_rd, stdout_buf, stdout_size, &out_total);
        if (stderr_buf && stderr_size > 1)
            drain_pipe(h_stderr_rd, stderr_buf, stderr_size, &err_total);

        if (wait_result == WAIT_OBJECT_0) {
            /* Process exited — drain remaining pipe data */
            Sleep(50); /* grace period: kernel may still be flushing pipe buffers */
            if (stdout_buf && stdout_size > 1)
                drain_pipe(h_stdout_rd, stdout_buf, stdout_size, &out_total);
            if (stderr_buf && stderr_size > 1)
                drain_pipe(h_stderr_rd, stderr_buf, stderr_size, &err_total);
            ret = 0;
            break;
        }

        if (wait_result == WAIT_TIMEOUT || wait_result == WAIT_FAILED) {
            TerminateProcess(pi.hProcess, 1);
            ret = -2;
            if (exit_code) *exit_code = -1;
            goto cleanup;
        }
        /* Otherwise: pipe data available — loop and wait again */
    }

    if (exit_code) {
        DWORD ec;
        if (GetExitCodeProcess(pi.hProcess, &ec))
            *exit_code = (int)ec;
        else
            *exit_code = -1;
    }

cleanup:
    if (h_stdout_rd) CloseHandle(h_stdout_rd);
    if (h_stdout_wr) CloseHandle(h_stdout_wr);
    if (h_stderr_rd) CloseHandle(h_stderr_rd);
    if (h_stderr_wr) CloseHandle(h_stderr_wr);
    if (pi.hProcess) CloseHandle(pi.hProcess);
    if (pi.hThread)  CloseHandle(pi.hThread);
    return ret;
}

#else /* POSIX / Linux */

#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <poll.h>
#include <errno.h>
#include <limits.h>
#include <time.h>

int subprocess_which(const char *cmd) {
    char test_path[PATH_MAX];
    char path_copy[32768];
    char *path_env, *dir;

    if (cmd[0] == '/')
        return access(cmd, X_OK) == 0 ? 1 : 0;

    path_env = getenv("PATH");
    if (!path_env) return 0;

    strncpy(path_copy, path_env, sizeof(path_copy) - 1);
    path_copy[sizeof(path_copy) - 1] = '\0';

    dir = strtok(path_copy, ":");
    while (dir) {
        snprintf(test_path, sizeof(test_path), "%s/%s", dir, cmd);
        if (access(test_path, X_OK) == 0) return 1;
        dir = strtok(NULL, ":");
    }
    return 0;
}

static void drain_fd(int fd, char *buf, size_t bufsize, size_t *total, int *open) {
    char discard[256];
    char *dst;
    size_t avail;
    ssize_t n;

    if (buf && *total < bufsize - 1) {
        dst   = buf + *total;
        avail = bufsize - *total - 1;
    } else {
        dst   = discard;
        avail = sizeof(discard);
    }

    n = read(fd, dst, avail);
    if (n > 0) {
        if (dst != discard) {
            *total += (size_t)n;
            buf[*total] = '\0';
        }
    } else {
        *open = 0;
    }
}

int subprocess_run(
    const char *cmd,
    char *const argv[],
    int timeout_sec,
    int *exit_code,
    char *stdout_buf,
    size_t stdout_size,
    char *stderr_buf,
    size_t stderr_size
) {
    int out_pipe[2], err_pipe[2];
    pid_t pid;
    int ret = -1;
    size_t out_total = 0, err_total = 0;
    int out_open = 1, err_open = 1;
    struct timespec deadline;

    (void)cmd;

    if (!argv) return -1;
    if (stdout_buf && stdout_size > 0) stdout_buf[0] = '\0';
    if (stderr_buf && stderr_size > 0) stderr_buf[0] = '\0';

    if (pipe(out_pipe) != 0) return -1;
    if (pipe(err_pipe) != 0) { close(out_pipe[0]); close(out_pipe[1]); return -1; }

    pid = fork();
    if (pid < 0) {
        close(out_pipe[0]); close(out_pipe[1]);
        close(err_pipe[0]); close(err_pipe[1]);
        return -1;
    }

    if (pid == 0) {
        close(out_pipe[0]);
        close(err_pipe[0]);
        dup2(out_pipe[1], STDOUT_FILENO);
        dup2(err_pipe[1], STDERR_FILENO);
        close(out_pipe[1]);
        close(err_pipe[1]);
        execvp(argv[0], argv);
        _exit(127);
    }

    close(out_pipe[1]);
    close(err_pipe[1]);

    if (timeout_sec > 0) {
        clock_gettime(CLOCK_MONOTONIC, &deadline);
        deadline.tv_sec += timeout_sec;
    }

    while (out_open || err_open) {
        struct pollfd fds[2];
        int timeout_ms = -1;

        if (timeout_sec > 0) {
            struct timespec now;
            long ms;
            clock_gettime(CLOCK_MONOTONIC, &now);
            ms = (deadline.tv_sec - now.tv_sec) * 1000L
               + (deadline.tv_nsec - now.tv_nsec) / 1000000L;
            if (ms <= 0) {
                kill(pid, SIGKILL);
                waitpid(pid, NULL, 0);
                ret = -2;
                if (exit_code) *exit_code = -1;
                goto cleanup;
            }
            timeout_ms = (int)ms;
        }

        fds[0].fd     = out_open ? out_pipe[0] : -1;
        fds[0].events = POLLIN;
        fds[1].fd     = err_open ? err_pipe[0] : -1;
        fds[1].events = POLLIN;

        if (poll(fds, 2, timeout_ms) < 0) {
            if (errno == EINTR) continue;
            break;
        }

        if (fds[0].revents & (POLLIN | POLLHUP | POLLERR))
            drain_fd(out_pipe[0], stdout_buf, stdout_size, &out_total, &out_open);
        else if (fds[0].revents & POLLNVAL)
            out_open = 0;

        if (fds[1].revents & (POLLIN | POLLHUP | POLLERR))
            drain_fd(err_pipe[0], stderr_buf, stderr_size, &err_total, &err_open);
        else if (fds[1].revents & POLLNVAL)
            err_open = 0;
    }

    {
        int status;
        waitpid(pid, &status, 0);
        if (exit_code)
            *exit_code = WIFEXITED(status) ? WEXITSTATUS(status) : -1;
    }
    ret = 0;

cleanup:
    close(out_pipe[0]);
    close(err_pipe[0]);
    return ret;
}

#endif /* _WIN32 */
