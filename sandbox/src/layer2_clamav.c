/* Layer 2: ClamAV integration via secure subprocess execution.
 *
 * Spawns clamdscan or clamscan as a child process using the Win32
 * CreateProcess API — no shell, no system(), immune to injection.
 * Parses output to extract virus names.
 */
#include "layer2_clamav.h"
#include "subprocess.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CLAMAV_TIMEOUT 30

/* Find first available ClamAV binary. Returns name or NULL. */
static const char *find_clamav(void) {
    static const char *bins[] = {"clamdscan.exe", "clamscan.exe",
                                 "clamdscan", "clamscan", NULL};
    int i;
    for (i = 0; bins[i]; i++) {
        if (subprocess_which(bins[i]))
            return bins[i];
    }
    return NULL;
}

/* Parse virus name from ClamAV output line.
 * Format: "/path/to/file: Virus.Name.Here FOUND"
 */
static void parse_virus_name(const char *output, char *name, size_t name_size) {
    const char *colon = strchr(output, ':');
    const char *found;
    size_t len;

    if (!colon) {
        snprintf(name, name_size, "%s", output);
        return;
    }

    colon++; /* skip colon */
    while (*colon == ' ') colon++;

    found = strstr(colon, "FOUND");
    if (found) {
        len = (size_t)(found - colon);
        while (len > 0 && colon[len-1] == ' ') len--;
        if (len >= name_size) len = name_size - 1;
        memmove(name, colon, len);
        name[len] = '\0';
    } else {
        snprintf(name, name_size, "%s", colon);
    }
}

Layer2Result layer2_scan(const char *file_path) {
    Layer2Result r;
    const char *clamav_bin;
    char *argv[8];
    char stdout_buf[8192];
    char stderr_buf[4096];
    int exit_code, spawn_ret;

    memset(&r, 0, sizeof(r));
    r.status = 2; /* default error */

    clamav_bin = find_clamav();
    if (!clamav_bin) {
        r.status = 2;
        snprintf(r.reason, sizeof(r.reason),
                 "ClamAV is not installed or not reachable on this system");
        return r;
    }

    /* Build argv: clamscan --no-summary --stdout <file> */
    argv[0] = (char *)clamav_bin;
    argv[1] = (char *)"--no-summary";
    argv[2] = (char *)"--stdout";
    argv[3] = (char *)file_path;
    argv[4] = NULL;

    spawn_ret = subprocess_run(
        clamav_bin, argv, CLAMAV_TIMEOUT,
        &exit_code,
        stdout_buf, sizeof(stdout_buf),
        stderr_buf, sizeof(stderr_buf)
    );

    if (spawn_ret == -1) {
        r.status = 2;
        snprintf(r.reason, sizeof(r.reason), "Failed to launch ClamAV scanner");
        return r;
    }
    if (spawn_ret == -2) {
        r.status = 2;
        snprintf(r.reason, sizeof(r.reason),
                 "ClamAV scan timed out after %d seconds", CLAMAV_TIMEOUT);
        return r;
    }

    /* clamscan exit codes: 0=clean, 1=virus found, 2=error */
    if (exit_code == 0) {
        r.status = 0; /* clean */
        return r;
    }

    if (exit_code == 1) {
        const char *output = stdout_buf[0] ? stdout_buf : stderr_buf;
        r.status = 1; /* infected */
        parse_virus_name(output, r.virus_name, sizeof(r.virus_name));
        if (r.virus_name[0]) {
            snprintf(r.reason, sizeof(r.reason),
                     "Malware detected: %s", r.virus_name);
        } else {
            snprintf(r.reason, sizeof(r.reason), "Malware detected: Unknown threat");
        }
        return r;
    }

    /* exit_code == 2 or other: error */
    r.status = 2;
    if (stderr_buf[0]) {
        snprintf(r.reason, sizeof(r.reason),
                 "ClamAV scan error (exit %d): %s", exit_code, stderr_buf);
    } else {
        snprintf(r.reason, sizeof(r.reason),
                 "ClamAV scan error (exit code %d)", exit_code);
    }
    return r;
}
