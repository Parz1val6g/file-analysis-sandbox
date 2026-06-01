/* Layer 1: Static Magic Bytes & Hex Signature Validation. */
#ifndef LAYER1_MAGIC_H
#define LAYER1_MAGIC_H

typedef struct {
    int    status;        /* 0=clean, 1=infected, 2=error */
    char   reason[512];
    char   true_type[256];
    char   declared_ext[32];
} Layer1Result;

Layer1Result layer1_validate(const char *file_path);

#endif /* LAYER1_MAGIC_H */
