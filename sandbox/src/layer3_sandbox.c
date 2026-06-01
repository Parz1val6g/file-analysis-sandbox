/* Layer 3: Docker sandbox implementation.
 *
 * Spawns a heavily restricted Docker container using CreateProcess
 * (no shell, no system()). Enforces: --rm, --network none, --read-only,
 * --cap-drop=ALL, --memory=256m, --cpus=0.5, with an 8-second timeout.
 * The single file is mounted read-only; zero host visibility.
 */
#include "layer3_sandbox.h"
#include "sha256.h"
#include "subprocess.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define SANDBOX_TIMEOUT    8
#define SANDBOX_IMAGE      "sandbox-extractor:latest"
#define MOUNT_POINT        "/sandbox/input_file:ro"

/* Check if Docker daemon is reachable */
static int docker_available(void) {
    char *argv[3];
    int exit_code;
    int ret;

    argv[0] = (char *)"docker";
    argv[1] = (char *)"info";
    argv[2] = NULL;

    ret = subprocess_run("docker", argv, 10, &exit_code, NULL, 0, NULL, 0);
    return (ret == 0 && exit_code == 0) ? 1 : 0;
}

/* Build the sandbox Docker image. Returns 0 on success. */
static int build_sandbox_image(char *error, size_t error_size) {
    char *argv[8];
    char stdout_buf[4096];
    char stderr_buf[4096];
    int exit_code, ret;

    /* Find the Docker directory relative to the executable */
    /* For simplicity, assume CWD is the sandbox/ directory */
    argv[0] = (char *)"docker";
    argv[1] = (char *)"build";
    argv[2] = (char *)"-t";
    argv[3] = (char *)SANDBOX_IMAGE;
    argv[4] = (char *)"-f";
    argv[5] = (char *)"docker/Dockerfile.sandbox";
    argv[6] = (char *)"docker/";
    argv[7] = NULL;

    ret = subprocess_run("docker", argv, 120,
                         &exit_code,
                         stdout_buf, sizeof(stdout_buf),
                         stderr_buf, sizeof(stderr_buf));

    if (ret != 0 || exit_code != 0) {
        if (error && error_size > 0) {
            snprintf(error, error_size, "docker build failed: %s",
                     stderr_buf[0] ? stderr_buf : "unknown error");
        }
        return -1;
    }
    return 0;
}

/* Convert Windows path to Docker-compatible format */
static void to_docker_path(const char *win_path, char *out, size_t out_size) {
    size_t i, j = 0;

    for (i = 0; win_path[i] && j < out_size - 1; i++) {
        if (win_path[i] == '\\')
            out[j++] = '/';
        else
            out[j++] = win_path[i];
    }
    out[j] = '\0';

    /* Add WSL-style prefix for Docker Desktop: C:/foo -> //c/foo */
    if (j >= 2 && out[1] == ':') {
        char tmp[4096];
        snprintf(tmp, sizeof(tmp), "/%c%s", out[0] + 32, out + 2);
        snprintf(out, out_size, "%s", tmp);
    }
}

Layer3Result layer3_execute(const char *file_path) {
    Layer3Result r;
    char docker_path[4096];
    char volume_arg[8192];
    char *argv[16];
    char stdout_buf[16384];
    char stderr_buf[4096];
    char build_err[1024];
    uint8_t hash[SHA256_DIGEST_SIZE];
    int exit_code, spawn_ret;

    memset(&r, 0, sizeof(r));
    r.status = 1; /* default error */

    /* Check Docker availability */
    if (!docker_available()) {
        r.status = 1;
        snprintf(r.reason, sizeof(r.reason),
                 "Docker is not available or daemon is not reachable");
        return r;
    }

    /* Compute SHA-256 of input file */
    if (sha256_file(file_path, hash) != 0) {
        r.status = 1;
        snprintf(r.reason, sizeof(r.reason), "Cannot hash input file");
        return r;
    }
    sha256_hex(hash, r.signature);

    /* Build sandbox image */
    if (build_sandbox_image(build_err, sizeof(build_err)) != 0) {
        r.status = 1;
        snprintf(r.reason, sizeof(r.reason),
                 "Cannot build sandbox image: %s", build_err);
        return r;
    }

    /* Convert path for Docker volume mount */
    to_docker_path(file_path, docker_path, sizeof(docker_path));
    snprintf(volume_arg, sizeof(volume_arg), "%s:%s", docker_path, MOUNT_POINT);

    /* Build docker run command with all security flags */
    argv[0]  = (char *)"docker";
    argv[1]  = (char *)"run";
    argv[2]  = (char *)"--rm";
    argv[3]  = (char *)"--network";
    argv[4]  = (char *)"none";
    argv[5]  = (char *)"--read-only";
    argv[6]  = (char *)"--cap-drop=ALL";
    argv[7]  = (char *)"--memory=256m";
    argv[8]  = (char *)"--cpus=0.5";
    argv[9]  = (char *)"-v";
    argv[10] = volume_arg;
    argv[11] = (char *)SANDBOX_IMAGE;
    argv[12] = (char *)MOUNT_POINT;
    argv[13] = NULL;

    spawn_ret = subprocess_run(
        "docker", argv, SANDBOX_TIMEOUT + 2,
        &exit_code,
        stdout_buf, sizeof(stdout_buf),
        stderr_buf, sizeof(stderr_buf)
    );

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
        r.status = 0; /* clean */
        /* Pass container output as metadata */
        snprintf(r.metadata_json, sizeof(r.metadata_json), "%s", stdout_buf);
    } else {
        r.status = 1;
        if (stderr_buf[0]) {
            snprintf(r.reason, sizeof(r.reason),
                     "Sandbox container exited with code %d: %s",
                     exit_code, stderr_buf);
        } else {
            snprintf(r.reason, sizeof(r.reason),
                     "Sandbox container exited with code %d", exit_code);
        }
    }

    return r;
}
