/* Secure subprocess execution — Windows API implementation.
 *
 * Uses CreateProcessW (Unicode) with explicit argument passing.
 * No shell, no cmd.exe — immune to command injection.
 * Pipes are read concurrently to prevent deadlocks.
 */
#include "subprocess.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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

    /* Wait loop with concurrent pipe draining (prevents deadlocks) */
    for (;;) {
        DWORD remaining = (DWORD)(timeout_sec > 0 ? timeout_sec * 1000 : INFINITE);

        /* Wait for process exit OR pipe data */
        HANDLE handles[3] = { pi.hProcess, h_stdout_rd, h_stderr_rd };
        DWORD nhandles = 1;
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
            Sleep(50); /* Small grace period for final pipe flush */
            if (stdout_buf) drain_pipe(h_stdout_rd, stdout_buf, stdout_size, &out_total);
            if (stderr_buf) drain_pipe(h_stderr_rd, stderr_buf, stderr_size, &err_total);
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
