/* Layer 1: Magic byte validation implementation.
 *
 * Reads file header and checks against known signatures.
 * Flags extension-mismatch attacks where an executable binary
 * is disguised under a non-executable extension.
 */
#include "layer1_magic.h"
#include <stdio.h>
#include <string.h>

#define MAX_HEADER 16

/* Magic byte signature entry */
typedef struct {
    const char *ext;
    const char *bytes;
    size_t      len;
    size_t      offset;
    const char *label;
} MagicEntry;

/* Executable signature entry */
typedef struct {
    const char *bytes;
    size_t      len;
    const char *label;
} ExecSig;

/* Known magic bytes for common formats */
static const MagicEntry MAGIC_BYTES[] = {
    {"pdf",   "%PDF",                   4,  0, "PDF Document"},
    {"png",   "\x89PNG\r\n\x1a\n",      8,  0, "PNG Image"},
    {"jpg",   "\xff\xd8\xff",           3,  0, "JPEG Image"},
    {"jpeg",  "\xff\xd8\xff",           3,  0, "JPEG Image"},
    {"gif",   "GIF8",                   4,  0, "GIF Image"},
    {"zip",   "PK\x03\x04",             4,  0, "ZIP Archive"},
    {"docx",  "PK\x03\x04",             4,  0, "Office Open XML Document"},
    {"bz2",   "BZh",                    3,  0, "Bzip2 Archive"},
    {"gz",    "\x1f\x8b",               2,  0, "Gzip Archive"},
    {"7z",    "7z\xbc\xaf'\x1c",        6,  0, "7-Zip Archive"},
    {"rar",   "Rar!\x1a\x07",           6,  0, "RAR Archive"},
    {"mp3",   "\xff\xfb",               2,  0, "MP3 Audio"},
    {"mp4",   "...ftyp",                7,  4, "MP4 Video"},
    {"ogg",   "OggS",                   4,  0, "OGG Media"},
    {"wav",   "RIFF",                   4,  0, "WAV Audio"},
    {"flac",  "fLaC",                   4,  0, "FLAC Audio"},
    {"sqlite","SQLite format 3\x00",    16, 0, "SQLite Database"},
    {NULL, NULL, 0, 0, NULL}
};

/* Known executable signatures (high-risk) */
static const ExecSig EXEC_SIGS[] = {
    {"MZ",            2, "Windows/DOS Executable (PE/COFF)"},
    {"\x7fELF",       4, "Unix/Linux ELF Binary"},
    {"\xca\xfe\xba\xbe", 4, "macOS Mach-O Fat Binary"},
    {"\xce\xfa\xed\xfe", 4, "macOS Mach-O 32-bit"},
    {"\xcf\xfa\xed\xfe", 4, "macOS Mach-O 64-bit"},
    {"\xfe\xed\xfa\xce", 4, "macOS Mach-O 64-bit (reverse)"},
    {NULL, 0, NULL}
};

/* Extensions that are explicitly allowed for executables */
static const char *EXECUTABLE_EXTS[] = {
    "exe", "dll", "sys", "elf", "bin", "so", "o", "a", "dylib", "com", "msi", NULL
};

static int is_exec_ext(const char *ext) {
    int i;
    for (i = 0; EXECUTABLE_EXTS[i]; i++)
        if (strcmp(ext, EXECUTABLE_EXTS[i]) == 0) return 1;
    return 0;
}

static const char *check_executable(const unsigned char *header, size_t hlen) {
    int i;
    for (i = 0; EXEC_SIGS[i].bytes; i++) {
        if (hlen >= EXEC_SIGS[i].len &&
            memcmp(header, EXEC_SIGS[i].bytes, EXEC_SIGS[i].len) == 0)
            return EXEC_SIGS[i].label;
    }
    return NULL;
}

static void get_extension(const char *path, char *ext, size_t ext_size) {
    const char *dot = strrchr(path, '.');
    const char *slash = strrchr(path, '/');
    const char *bslash = strrchr(path, '\\');

    /* Find last path separator */
    if (slash && (!bslash || slash > bslash)) {
        if (dot && dot > slash) dot = dot;
        else dot = NULL;
    } else if (bslash) {
        if (dot && dot > bslash) dot = dot;
        else dot = NULL;
    }

    if (dot && dot[1]) {
        size_t i;
        const char *p = dot + 1;
        for (i = 0; i < ext_size - 1 && *p; i++, p++)
            ext[i] = (char)((*p >= 'A' && *p <= 'Z') ? *p + 32 : *p);
        ext[i] = '\0';
    } else {
        ext[0] = '\0';
    }
}

Layer1Result layer1_validate(const char *file_path) {
    Layer1Result r;
    unsigned char header[MAX_HEADER];
    size_t hlen;
    FILE *f;
    char ext[32];
    const char *exec_type;
    int i;

    memset(&r, 0, sizeof(r));
    r.status = 2; /* default error */

    get_extension(file_path, ext, sizeof(ext));

    if (ext[0] == '\0') {
        r.status = 0;
        snprintf(r.reason, sizeof(r.reason), "No extension; skipping magic byte check");
        return r;
    }

    f = fopen(file_path, "rb");
    if (!f) {
        r.status = 2;
        snprintf(r.reason, sizeof(r.reason), "Cannot open file for hex analysis");
        return r;
    }
    hlen = fread(header, 1, MAX_HEADER, f);
    fclose(f);

    if (hlen == 0) {
        r.status = 2;
        snprintf(r.reason, sizeof(r.reason), "Cannot read file header");
        return r;
    }

    /* Check for executable masquerading */
    exec_type = check_executable(header, hlen);
    if (exec_type && !is_exec_ext(ext)) {
        r.status = 1; /* infected */
        snprintf(r.reason, sizeof(r.reason),
                 "Extension mismatch attack: '.%s' extension but binary header matches %s",
                 ext, exec_type);
        snprintf(r.true_type, sizeof(r.true_type), "%s", exec_type);
        snprintf(r.declared_ext, sizeof(r.declared_ext), "%s", ext);
        return r;
    }

    /* Check declared extension against magic bytes */
    for (i = 0; MAGIC_BYTES[i].ext; i++) {
        if (strcmp(ext, MAGIC_BYTES[i].ext) == 0) {
            size_t off = MAGIC_BYTES[i].offset;
            if (hlen >= off + MAGIC_BYTES[i].len) {
                if (memcmp(header + off, MAGIC_BYTES[i].bytes, MAGIC_BYTES[i].len) != 0) {
                    r.status = 1;
                    snprintf(r.reason, sizeof(r.reason),
                             "Magic byte mismatch: expected %s for '.%s'",
                             MAGIC_BYTES[i].label, ext);
                    snprintf(r.true_type, sizeof(r.true_type), "unknown");
                    snprintf(r.declared_ext, sizeof(r.declared_ext), "%s", ext);
                    return r;
                }
            }
            break;
        }
    }

    r.status = 0;
    snprintf(r.declared_ext, sizeof(r.declared_ext), "%s", ext);
    return r;
}
