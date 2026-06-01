/* Secure subprocess execution — Windows API implementation.
 *
 * Uses CreateProcessW (Unicode) with explicit argument passing.
 * No shell, no cmd.exe — immune to command injection.
 * Pipes are used to capture stdout/stderr independently.
 * waitpid() equivalent via WaitForSingleObject with timeout.
 */
#include "subprocess.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>

/* Max combined command-line length before we give up */
#define MAX_CMDLINE 32768

static int build_cmdline(char *const argv[], wchar_t *out, size_t out_chars) {
    /* Build a properly quoted command line from argv[] */
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

        /* Check if quoting is needed */
        for (p = arg; *p; p++) {
            if (*p == ' ' || *p == '\t' || *p == '"') { needs_quote = 1; break; }
        }
        if (arg[0] == '\0') needs_quote = 1;

        if (needs_quote) {
            if (pos + 1 >= out_chars) return -1;
            out[pos++] = L'"';
            for (p = arg; *p; p++) {
                int backslashes = 0;
                /* Count backslashes before a quote */
                while (*p == '\\') { backslashes++; p++; }
                if (*p == '"') {
                    /* Double the backslashes and escape the quote */
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
                    /* Trailing backslashes */
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

int subprocess_which(const char *cmd) {
    /* On Windows, just try to find the executable */
    char which_cmd[1024];
    int n = snprintf(which_cmd, sizeof(which_cmd), "where %s 2>nul", cmd);
    if (n < 0 || (size_t)n >= sizeof(which_cmd)) return 0;

    /* Use a lightweight check — just see if CreateProcess can find it */
    STARTUPINFOW si;
    PROCESS_INFORMATION pi;
    wchar_t wcmd[512];
    int i;

    memset(&si, 0, sizeof(si));
    si.cb = sizeof(si);
    memset(&pi, 0, sizeof(pi));

    for (i = 0; cmd[i] && i < 510; i++) wcmd[i] = (wchar_t)(unsigned char)cmd[i];
    wcmd[i] = L'\0';

    if (CreateProcessW(NULL, wcmd, NULL, NULL, FALSE,
                       CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return 1;
    }
    return 0;
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
    DWORD wait_result, avail;
    int ret = -1;

    if (!cmd || !argv) return -1;

    /* Init output buffers */
    if (stdout_buf && stdout_size > 0) stdout_buf[0] = '\0';
    if (stderr_buf && stderr_size > 0) stderr_buf[0] = '\0';

    /* Security attributes for inheritable handles */
    memset(&sa, 0, sizeof(sa));
    sa.nLength = sizeof(sa);
    sa.bInheritHandle = TRUE;
    sa.lpSecurityDescriptor = NULL;

    /* Create pipes for stdout */
    if (!CreatePipe(&h_stdout_rd, &h_stdout_wr, &sa, 0)) goto cleanup;
    if (!SetHandleInformation(h_stdout_rd, HANDLE_FLAG_INHERIT, 0)) goto cleanup;

    /* Create pipes for stderr */
    if (!CreatePipe(&h_stderr_rd, &h_stderr_wr, &sa, 0)) goto cleanup;
    if (!SetHandleInformation(h_stderr_rd, HANDLE_FLAG_INHERIT, 0)) goto cleanup;

    /* Build command line */
    if (build_cmdline(argv, wcmd, MAX_CMDLINE / 2) != 0) goto cleanup;

    /* Startup info */
    memset(&si, 0, sizeof(si));
    si.cb = sizeof(si);
    si.hStdOutput = h_stdout_wr;
    si.hStdError  = h_stderr_wr;
    si.hStdInput  = GetStdHandle(STD_INPUT_HANDLE);
    si.dwFlags    = STARTF_USESTDHANDLES;

    memset(&pi, 0, sizeof(pi));

    /* Spawn */
    if (!CreateProcessW(
            NULL,              /* lpApplicationName — let system resolve from cmdline */
            wcmd,              /* lpCommandLine */
            NULL, NULL,        /* process/thread security */
            TRUE,              /* inherit handles */
            CREATE_NO_WINDOW,  /* dwCreationFlags */
            NULL, NULL,        /* environment / cwd */
            &si, &pi)) {
        goto cleanup;
    }

    /* Close write ends so reads don't hang */
    CloseHandle(h_stdout_wr); h_stdout_wr = NULL;
    CloseHandle(h_stderr_wr); h_stderr_wr = NULL;

    /* Wait with timeout */
    if (timeout_sec > 0) {
        wait_result = WaitForSingleObject(pi.hProcess, (DWORD)(timeout_sec * 1000));
    } else {
        wait_result = WaitForSingleObject(pi.hProcess, INFINITE);
    }

    if (wait_result == WAIT_TIMEOUT) {
        TerminateProcess(pi.hProcess, 1);
        ret = -2;
        if (exit_code) *exit_code = -1;
        goto cleanup;
    }

    /* Read stdout */
    if (stdout_buf && stdout_size > 1) {
        DWORD nread = 0, total = 0;
        while (PeekNamedPipe(h_stdout_rd, NULL, 0, NULL, &avail, NULL) && avail > 0) {
            DWORD to_read = (avail < (stdout_size - total - 1)) ? avail : (DWORD)(stdout_size - total - 1);
            if (to_read == 0) break;
            if (!ReadFile(h_stdout_rd, stdout_buf + total, to_read, &nread, NULL) || nread == 0)
                break;
            total += nread;
        }
        if (total < stdout_size) stdout_buf[total] = '\0';
    }

    /* Read stderr */
    if (stderr_buf && stderr_size > 1) {
        DWORD nread = 0, total = 0;
        while (PeekNamedPipe(h_stderr_rd, NULL, 0, NULL, &avail, NULL) && avail > 0) {
            DWORD to_read = (avail < (stderr_size - total - 1)) ? avail : (DWORD)(stderr_size - total - 1);
            if (to_read == 0) break;
            if (!ReadFile(h_stderr_rd, stderr_buf + total, to_read, &nread, NULL) || nread == 0)
                break;
            total += nread;
        }
        if (total < stderr_size) stderr_buf[total] = '\0';
    }

    /* Get exit code */
    if (exit_code) {
        DWORD ec;
        if (GetExitCodeProcess(pi.hProcess, &ec))
            *exit_code = (int)ec;
        else
            *exit_code = -1;
    }

    ret = 0;  /* success */

cleanup:
    if (h_stdout_rd) CloseHandle(h_stdout_rd);
    if (h_stdout_wr) CloseHandle(h_stdout_wr);
    if (h_stderr_rd) CloseHandle(h_stderr_rd);
    if (h_stderr_wr) CloseHandle(h_stderr_wr);
    if (pi.hProcess) CloseHandle(pi.hProcess);
    if (pi.hThread)  CloseHandle(pi.hThread);
    return ret;
}
