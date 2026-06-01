/* SHA-256 implementation — FIPS 180-4 compliant, zero external dependencies.
 *
 * Provides streaming (init/update/final) and one-shot APIs.
 * All functions are reentrant and const-correct.
 */
#ifndef SHA256_H
#define SHA256_H

#include <stddef.h>
#include <stdint.h>

#define SHA256_DIGEST_SIZE  32
#define SHA256_HEX_SIZE     65   /* 64 hex chars + NUL */
#define SHA256_BLOCK_SIZE   64

typedef struct {
    uint32_t state[8];
    uint64_t bitlen;
    uint8_t  block[SHA256_BLOCK_SIZE];
    size_t   blocklen;
} Sha256Ctx;

void sha256_init(Sha256Ctx *ctx);
void sha256_update(Sha256Ctx *ctx, const uint8_t *data, size_t len);
void sha256_final(Sha256Ctx *ctx, uint8_t hash[SHA256_DIGEST_SIZE]);

/* One-shot hash of a buffer */
void sha256_hash(const uint8_t *data, size_t len, uint8_t out[SHA256_DIGEST_SIZE]);

/* Hash an entire file; returns 0 on success, -1 on error */
int  sha256_file(const char *path, uint8_t out[SHA256_DIGEST_SIZE]);

/* Convert 32-byte binary hash to 65-byte lowercase hex string (NUL-terminated) */
void sha256_hex(const uint8_t hash[SHA256_DIGEST_SIZE], char out[SHA256_HEX_SIZE]);

#endif /* SHA256_H */
