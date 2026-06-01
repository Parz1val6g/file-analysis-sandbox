/* Sandbox File Analysis & Ephemeral Execution Engine — C Edition.
 *
 * Usage:  sandbox_engine <file_path>
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

#include "validation.h"
#include "layer1_magic.h"
#include "layer2_clamav.h"
#include "layer3_sandbox.h"
#include "json_builder.h"

/* Emit final JSON to stdout. This is the ONLY write to stdout. */
static void emit(const char *json) {
    fprintf(stdout, "%s\n", json);
    fflush(stdout);
}

/* Log diagnostic to stderr. */
static void log_msg(const char *msg) {
    fprintf(stderr, "[engine] %s\n", msg);
    fflush(stderr);
}

int main(int argc, char *argv[]) {
    char error[512];
    Layer1Result l1;
    Layer2Result l2;
    Layer3Result l3;
    JsonBuf jb;
    int clamav_skipped = 0;
    char clamav_reason[512] = "";

    /* ---- Argument validation ---- */
    if (argc != 2) {
        emit("{\"status\":\"error\",\"reason\":\"Usage: sandbox_engine <file_path>\"}");
        return 1;
    }

    /* ---- Input validation ---- */
    if (validate_input(argv[1], error, sizeof(error)) != 0) {
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
    log_msg("Layer 1: Magic byte validation...");
    l1 = layer1_validate(argv[1]);

    if (l1.status != 0) { /* not clean */
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
    log_msg("Layer 2: ClamAV scan...");
    l2 = layer2_scan(argv[1]);

    if (l2.status == 1) { /* infected */
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

    if (l2.status == 2) { /* error — graceful bypass */
        char bypass_msg[600];
        snprintf(bypass_msg, sizeof(bypass_msg), "Layer 2 BYPASSED: %s", l2.reason);
        log_msg(bypass_msg);
        clamav_skipped = 1;
        snprintf(clamav_reason, sizeof(clamav_reason), "%s", l2.reason);
    } else {
        log_msg("Layer 2 PASSED");
    }

    /* ==== LAYER 3: Docker Sandbox ==== */
    log_msg("Layer 3: Sandbox execution...");
    l3 = layer3_execute(argv[1]);

    if (json_init(&jb, 4096) != 0) {
        emit("{\"status\":\"error\",\"reason\":\"JSON buffer allocation failed\"}");
        return 1;
    }

    json_obj_open(&jb);

    if (l3.status == 0) { /* clean */
        json_add_str(&jb, "status", "clean");
        if (l3.signature[0])
            json_add_str(&jb, "signature", l3.signature);

        /* metadata object */
        json_nested_open(&jb, "metadata");

        /* Append raw container output first, then ClamAV skip info */
        if (l3.metadata_json[0])
            json_append_raw(&jb, l3.metadata_json);

        if (clamav_skipped) {
            json_add_bool(&jb, "clamav_skipped", 1);
            json_add_str(&jb, "clamav_skip_reason", clamav_reason);
        }

        json_nested_close(&jb); /* metadata */
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
