/* Layer 3: Docker sandbox implementation.
 *
 * Spawns a heavily restricted Docker container using CreateProcess.
 * Enforces: --rm, --network none, --read-only, --cap-drop=ALL,
 * --memory=256m, --memory-swap=256m, --cpus=0.5, 8-second timeout.
 *
 * The image is built once (cached) and the build context is resolved
 * relative to the executable location, not CWD.
 */
#include "layer3_sandbox.h"
#include "sha256.h"
#include "subprocess.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <windows.h>
#else
#include <unistd.h>
#include <limits.h>
#endif

#define SANDBOX_TIMEOUT    8
#define SANDBOX_IMAGE      "sandbox-extractor:latest"
#define MOUNT_TARGET       "/sandbox/input_file"

/* Resolve the sandbox root directory (where Dockerfile lives) */
static void get_sandbox_root(char *buf, size_t size) {
#ifdef _WIN32
    wchar_t wpath[MAX_PATH];
    DWORD len = GetModuleFileNameW(NULL, wpath, MAX_PATH);
    if (len > 0 && len < MAX_PATH) {
        /* Find the last backslash (directory containing the exe) */
        wchar_t *slash = wcsrchr(wpath, L'\\');
        if (slash) *slash = L'\0';
        /* Convert back to char (ASCII-safe) */
        int i;
        for (i = 0; i < (int)size - 1 && wpath[i]; i++)
            buf[i] = (char)wpath[i];
        buf[i] = '\0';
    } else {
        snprintf(buf, size, ".");
    }
#else
    char exe_path[PATH_MAX];
    ssize_t len = readlink("/proc/self/exe", exe_path, sizeof(exe_path) - 1);
    if (len > 0) {
        exe_path[len] = '\0';
        char *slash = strrchr(exe_path, '/');
        if (slash) *slash = '\0';
        snprintf(buf, size, "%s", exe_path);
    } else {
        snprintf(buf, size, ".");
    }
#endif
}

static int docker_available(void) {
    char *argv[3];
    int exit_code;
    argv[0] = (char *)"docker";
    argv[1] = (char *)"info";
    argv[2] = NULL;
    return (subprocess_run("docker", argv, 10, &exit_code, NULL, 0, NULL, 0) == 0
            && exit_code == 0) ? 1 : 0;
}

/* Check if sandbox image exists; build only if missing */
static int ensure_sandbox_image(char *error, size_t error_size) {
    char *inspect_argv[4];
    char stdout_buf[4096], stderr_buf[4096];
    char build_err[1024];
    int exit_code, ret;
    char root[1024];
    char dockerfile[2048];
    char context[2048];

    /* Check if image already exists */
    inspect_argv[0] = (char *)"docker";
    inspect_argv[1] = (char *)"image";
    inspect_argv[2] = (char *)"inspect";
    inspect_argv[3] = (char *)SANDBOX_IMAGE;
    inspect_argv[4] = NULL;

    ret = subprocess_run("docker", inspect_argv, 10, &exit_code,
                         stdout_buf, sizeof(stdout_buf),
                         stderr_buf, sizeof(stderr_buf));
    if (ret == 0 && exit_code == 0)
        return 0; /* Image exists */

    /* Build the image using paths relative to exe location */
    get_sandbox_root(root, sizeof(root));
    snprintf(dockerfile, sizeof(dockerfile), "%s/docker/Dockerfile.sandbox", root);
    snprintf(context, sizeof(context), "%s/docker", root);

    char *build_argv[8];
    build_argv[0] = (char *)"docker";
    build_argv[1] = (char *)"build";
    build_argv[2] = (char *)"-t";
    build_argv[3] = (char *)SANDBOX_IMAGE;
    build_argv[4] = (char *)"-f";
    build_argv[5] = dockerfile;
    build_argv[6] = context;
    build_argv[7] = NULL;

    ret = subprocess_run("docker", build_argv, 120, &exit_code,
                         stdout_buf, sizeof(stdout_buf),
                         stderr_buf, sizeof(stderr_buf));
    if (ret != 0 || exit_code != 0) {
        if (error && error_size > 0)
            snprintf(error, error_size, "docker build failed: %s",
                     stderr_buf[0] ? stderr_buf : "unknown error");
        return -1;
    }
    return 0;
}

/* Convert Windows path to Docker-compatible format (host_mnt style) */
static void to_docker_path(const char *win_path, char *out, size_t out_size) {
    size_t i, j = 0;
    int has_drive = 0;

    for (i = 0; win_path[i] && j < out_size - 1; i++) {
        if (win_path[i] == '\\')
            out[j++] = '/';
        else
            out[j++] = win_path[i];
    }
    out[j] = '\0';

    /* Docker Desktop expects /host_mnt/c/... not //c/... */
    if (j >= 2 && out[1] == ':') {
        char tmp[4096];
        snprintf(tmp, sizeof(tmp), "/host_mnt/%c%s",
                 out[0] + ('a' - 'A'), out + 2);
        snprintf(out, out_size, "%s", tmp);
    }
}

/* Kill a Docker container by ID */
static void docker_rm(const char *container_id) {
    char *argv[4];
    argv[0] = (char *)"docker";
    argv[1] = (char *)"rm";
    argv[2] = (char *)"-f";
    argv[3] = (char *)container_id;
    argv[4] = NULL;
    int dummy;
    subprocess_run("docker", argv, 5, &dummy, NULL, 0, NULL, 0);
}

Layer3Result layer3_execute(const char *file_path) {
    Layer3Result r;
    char docker_path[4096];
    char volume_arg[8192];
    char *argv[19];
    char stdout_buf[16384];
    char stderr_buf[4096];
    char build_err[1024];
    uint8_t hash[SHA256_DIGEST_SIZE];
    int exit_code, spawn_ret;

    memset(&r, 0, sizeof(r));
    r.status = 1;

    if (!docker_available()) {
        r.status = 1;
        snprintf(r.reason, sizeof(r.reason),
                 "Docker is not available or daemon is not reachable");
        return r;
    }

    if (sha256_file(file_path, hash) != 0) {
        r.status = 1;
        snprintf(r.reason, sizeof(r.reason), "Cannot hash input file");
        return r;
    }
    sha256_hex(hash, r.signature);

    if (ensure_sandbox_image(build_err, sizeof(build_err)) != 0) {
        r.status = 1;
        snprintf(r.reason, sizeof(r.reason),
                 "Cannot build sandbox image: %s", build_err);
        return r;
    }

    to_docker_path(file_path, docker_path, sizeof(docker_path));
    snprintf(volume_arg, sizeof(volume_arg), "%s:%s:ro", docker_path, MOUNT_TARGET);

    /* Build docker run command */
    argv[0]  = (char *)"docker";
    argv[1]  = (char *)"run";
    argv[2]  = (char *)"--rm";
    argv[3]  = (char *)"--network";
    argv[4]  = (char *)"none";
    argv[5]  = (char *)"--read-only";
    argv[6]  = (char *)"--cap-drop=ALL";
    argv[7]  = (char *)"--memory=256m";
    argv[8]  = (char *)"--memory-swap=256m";
    argv[9]  = (char *)"--cpus=0.5";
    argv[10] = (char *)"-v";
    argv[11] = volume_arg;
    argv[12] = (char *)SANDBOX_IMAGE;
    argv[13] = (char *)MOUNT_TARGET;
    argv[14] = NULL;

    spawn_ret = subprocess_run("docker", argv, SANDBOX_TIMEOUT + 2,
                               &exit_code,
                               stdout_buf, sizeof(stdout_buf),
                               stderr_buf, sizeof(stderr_buf));

    if (spawn_ret == -2) {
        r.status = 1;
        snprintf(r.reason, sizeof(r.reason),
                 "Sandbox execution timed out after %d seconds", SANDBOX_TIMEOUT);
        return r;
    }

    if (spawn_ret != 0) {
        r.status = 1;
        snprintf(r.reason, sizeof(r.reason), "Failed to launch sandbox container");
        return r;
    }

    if (exit_code == 0 && stdout_buf[0]) {
        r.status = 0;
        snprintf(r.metadata_json, sizeof(r.metadata_json), "%s", stdout_buf);
    } else {
        r.status = 1;
        if (stderr_buf[0]) {
            snprintf(r.reason, sizeof(r.reason),
                     "Sandbox container error (code %d): %s",
                     exit_code, stderr_buf);
        } else {
            snprintf(r.reason, sizeof(r.reason),
                     "Sandbox container error (code %d)", exit_code);
        }
    }

    return r;
}
