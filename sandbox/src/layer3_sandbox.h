/* Layer 3: Ephemeral Docker Sandbox Execution Engine. */
#ifndef LAYER3_SANDBOX_H
#define LAYER3_SANDBOX_H

typedef struct {
    int    status;        /* 0=clean, 1=error */
    char   reason[512];
    char   signature[65];   /* SHA-256 hex */
    char   metadata_json[16384];
} Layer3Result;

Layer3Result layer3_execute(const char *file_path);

#endif /* LAYER3_SANDBOX_H */
