/* Sandbox File Analysis & Ephemeral Execution Engine — C Edition.
 *
 * Usage:  sandbox_engine <file_path>
 *         sandbox_engine --version
 *         sandbox_engine --help
 *
 * Processes an untrusted file through three air-gapped security layers.
 * Outputs a single JSON line to stdout. ALL diagnostics go to stderr.
 *
 * Zero external dependencies — libc + Win32 API only.
 * Self-contained SHA-256, JSON builder, subprocess manager.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>

#ifdef _WIN32
#include <windows.h>
#endif

#include "validation.h"
#include "layer1_magic.h"
#include "layer2_clamav.h"
#include "layer3_sandbox.h"
#include "json_builder.h"

#define VERSION "1.0.0"

/* ---- Global for signal handler ---- */
static volatile int g_interrupted = 0;

#ifdef _WIN32
static BOOL WINAPI ctrl_handler(DWORD ctrl_type) {
    if (ctrl_type == CTRL_C_EVENT || ctrl_type == CTRL_BREAK_EVENT) {
        g_interrupted = 1;
        /* Emit error JSON immediately before the OS kills us */
        fprintf(stdout, "{\"status\":\"error\",\"reason\":\"Engine interrupted by signal\"}\n");
        fflush(stdout);
        return TRUE; /* We handled it */
    }
    return FALSE;
}
#else
static void sig_handler(int sig) {
    g_interrupted = 1;
    fprintf(stdout, "{\"status\":\"error\",\"reason\":\"Engine interrupted by signal %d\"}\n", sig);
    fflush(stdout);
    _exit(1);
}
#endif

/* ---- Helpers ---- */

static void emit(const char *json) {
    fprintf(stdout, "%s\n", json);
    fflush(stdout);
}

static void log_msg(const char *msg) {
    fprintf(stderr, "[engine] %s\n", msg);
    fflush(stderr);
}

static void print_help(void) {
    fprintf(stdout,
        "sandbox_engine v" VERSION " — File Analysis & Ephemeral Sandbox Engine\n"
        "\n"
        "Usage:\n"
        "  sandbox_engine <file_path>       Analyze a file through 3 security layers\n"
        "  sandbox_engine --version          Print version and exit\n"
        "  sandbox_engine --help             Print this help\n"
        "\n"
        "Output:\n"
        "  A single JSON line to stdout. All diagnostics go to stderr.\n"
        "\n"
        "Exit codes:\n"
        "  0  File is clean\n"
        "  1  Infected, error, or invalid arguments\n"
    );
}

/* ---- Main ---- */

int main(int argc, char *argv[]) {
    char error[512];
    Layer1Result l1 = {0};
    Layer2Result l2 = {0};
    Layer3Result l3 = {0};
    JsonBuf jb = {0};
    int clamav_skipped = 0;
    char clamav_reason[512] = "";
    const char *file_path;

    /* Install signal/ctrl-c handler early */
#ifdef _WIN32
    SetConsoleCtrlHandler(ctrl_handler, TRUE);
#else
    signal(SIGINT,  sig_handler);
    signal(SIGTERM, sig_handler);
#endif

    /* ---- Argument handling ---- */
    if (argc == 2 && strcmp(argv[1], "--help") == 0) {
        print_help();
        return 0;
    }
    if (argc == 2 && strcmp(argv[1], "--version") == 0) {
        fprintf(stdout, "sandbox_engine v" VERSION "\n");
        return 0;
    }
    if (argc != 2) {
        emit("{\"status\":\"error\",\"reason\":\"Usage: sandbox_engine <file_path>\"}");
        return 1;
    }

    file_path = argv[1];

    /* ---- Input validation ---- */
    if (validate_input(file_path, error, sizeof(error)) != 0) {
        if (json_init(&jb, 512) == 0) {
            json_obj_open(&jb);
            json_add_str(&jb, "status", "error");
            json_add_str(&jb, "reason", error);
            json_obj_close(&jb);
            emit(json_cstr(&jb));
            json_free(&jb);
        } else {
            emit("{\"status\":\"error\",\"reason\":\"Input validation failed\"}");
        }
        return 1;
    }

    /* ==== LAYER 1: Magic Bytes ==== */
    if (g_interrupted) { emit("{\"status\":\"error\",\"reason\":\"Interrupted\"}"); return 1; }
    log_msg("Layer 1: Magic byte validation...");
    l1 = layer1_validate(file_path);

    if (l1.status != 0) {
        if (json_init(&jb, 512) == 0) {
            json_obj_open(&jb);
            json_add_str(&jb, "status", l1.status == 1 ? "infected" : "error");
            if (l1.reason[0])
                json_add_str(&jb, "reason", l1.reason);
            if (l1.true_type[0])
                json_add_str(&jb, "true_type", l1.true_type);
            if (l1.declared_ext[0])
                json_add_str(&jb, "declared_extension", l1.declared_ext);
            json_obj_close(&jb);
            emit(json_cstr(&jb));
            json_free(&jb);
        }
        log_msg("Layer 1 FAILED");
        return 1;
    }
    log_msg("Layer 1 PASSED");

    /* ==== LAYER 2: ClamAV ==== */
    if (g_interrupted) { emit("{\"status\":\"error\",\"reason\":\"Interrupted\"}"); return 1; }
    log_msg("Layer 2: ClamAV scan...");
    l2 = layer2_scan(file_path);

    if (l2.status == 1) {
        if (json_init(&jb, 512) == 0) {
            json_obj_open(&jb);
            json_add_str(&jb, "status", "infected");
            json_add_str(&jb, "reason", l2.reason);
            if (l2.virus_name[0])
                json_add_str(&jb, "virus_name", l2.virus_name);
            json_obj_close(&jb);
            emit(json_cstr(&jb));
            json_free(&jb);
        }
        log_msg("Layer 2 FAILED (infected)");
        return 1;
    }

    if (l2.status == 2) {
        char bypass_msg[600];
        snprintf(bypass_msg, sizeof(bypass_msg), "Layer 2 BYPASSED: %s", l2.reason);
        log_msg(bypass_msg);
        clamav_skipped = 1;
        snprintf(clamav_reason, sizeof(clamav_reason), "%s", l2.reason);
    } else {
        log_msg("Layer 2 PASSED");
    }

    /* ==== LAYER 3: Docker Sandbox ==== */
    if (g_interrupted) { emit("{\"status\":\"error\",\"reason\":\"Interrupted\"}"); return 1; }
    log_msg("Layer 3: Sandbox execution...");
    l3 = layer3_execute(file_path);

    if (json_init(&jb, 4096) != 0) {
        emit("{\"status\":\"error\",\"reason\":\"JSON buffer allocation failed\"}");
        return 1;
    }

    json_obj_open(&jb);

    if (l3.status == 0) {
        json_add_str(&jb, "status", "clean");
        if (l3.signature[0])
            json_add_str(&jb, "signature", l3.signature);

        json_nested_open(&jb, "metadata");

        /* Validate container output before appending raw JSON */
        if (l3.metadata_json[0]) {
            const char *raw = l3.metadata_json;
            while (*raw == ' ' || *raw == '\n' || *raw == '\r') raw++;
            if (*raw == '{' || *raw == '[')
                json_append_raw(&jb, raw);
        }

        if (clamav_skipped) {
            json_add_bool(&jb, "clamav_skipped", 1);
            json_add_str(&jb, "clamav_skip_reason", clamav_reason);
        }

        json_nested_close(&jb);
        log_msg("Layer 3 PASSED — file is clean");
    } else {
        json_add_str(&jb, "status", "error");
        if (l3.reason[0])
            json_add_str(&jb, "reason", l3.reason);
        if (l3.signature[0])
            json_add_str(&jb, "signature", l3.signature);
        log_msg("Layer 3 ERROR");
    }

    json_obj_close(&jb);
    emit(json_cstr(&jb));
    json_free(&jb);

    return (l3.status == 0) ? 0 : 1;
}
