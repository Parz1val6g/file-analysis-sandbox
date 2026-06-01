/* Sandbox file extractor — runs INSIDE the ephemeral Docker container.
 *
 * Receives a file path as argument, detects MIME type, extracts text
 * using available tools (pdftotext, tesseract, file), and prints
 * a JSON metadata object to stdout.
 *
 * Compiled inside Dockerfile.sandbox via multi-stage build.
 * Zero dependencies beyond libc + external CLI tools.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#define MAX_BUF 65536

/* Read entire output from popen, return malloc'd string. Caller frees. */
static char *read_cmd(const char *cmd) {
    FILE *fp;
    char *buf;
    size_t len = 0, cap = 4096;

    buf = (char *)malloc(cap);
    if (!buf) return NULL;
    buf[0] = '\0';

    fp = popen(cmd, "r");
    if (!fp) { free(buf); return NULL; }

    while (fgets(buf + len, (int)(cap - len), fp)) {
        len = strlen(buf);
        if (cap - len < 1024) {
            cap *= 2;
            char *tmp = (char *)realloc(buf, cap);
            if (!tmp) { free(buf); pclose(fp); return NULL; }
            buf = tmp;
        }
    }
    pclose(fp);

    /* Remove trailing newlines */
    while (len > 0 && (buf[len-1] == '\n' || buf[len-1] == '\r'))
        buf[--len] = '\0';
    return buf;
}

/* JSON-escape a string and write to stdout */
static void json_str(const char *s) {
    putchar('"');
    while (*s) {
        unsigned char c = (unsigned char)*s;
        switch (c) {
        case '"':  printf("\\\""); break;
        case '\\': printf("\\\\"); break;
        case '\n': printf("\\n"); break;
        case '\r': printf("\\r"); break;
        case '\t': printf("\\t"); break;
        default:
            if (c < 0x20) printf("\\u%04x", c);
            else putchar(c);
            break;
        }
        s++;
    }
    putchar('"');
}

/* JSON-escape a string into a malloc'd buffer */
static char *json_escape(const char *s) {
    size_t len = 0, cap = 256;
    char *buf = (char *)malloc(cap);
    if (!buf) return NULL;
    buf[0] = '\0';

    while (*s) {
        unsigned char c = (unsigned char)*s;
        char esc[16]; int elen = 0;

        switch (c) {
        case '"':  esc[0]='\\'; esc[1]='"';  elen=2; break;
        case '\\': esc[0]='\\'; esc[1]='\\'; elen=2; break;
        case '\n': esc[0]='\\'; esc[1]='n';  elen=2; break;
        case '\r': esc[0]='\\'; esc[1]='r';  elen=2; break;
        case '\t': esc[0]='\\'; esc[1]='t';  elen=2; break;
        default:
            if (c < 0x20) elen = snprintf(esc, sizeof(esc), "\\u%04x", c);
            else { esc[0]=(char)c; elen=1; }
            break;
        }

        if (len + elen + 1 >= cap) {
            cap *= 2;
            char *tmp = (char *)realloc(buf, cap);
            if (!tmp) { free(buf); return NULL; }
            buf = tmp;
        }
        memmove(buf + len, esc, (size_t)elen);
        len += (size_t)elen;
        buf[len] = '\0';
        s++;
    }
    return buf;
}

static long long file_size(const char *path) {
    struct stat st;
    if (stat(path, &st) != 0) return -1;
    return (long long)st.st_size;
}

int main(int argc, char *argv[]) {
    char *mime = NULL, *extracted = NULL, *escaped = NULL;
    char cmd[4096];
    long long fsize;

    if (argc != 2) {
        fprintf(stderr, "Usage: extractor <file_path>\n");
        return 1;
    }

    /* Detect MIME type */
    snprintf(cmd, sizeof(cmd), "file --mime-type -b \"%s\" 2>/dev/null", argv[1]);
    mime = read_cmd(cmd);
    if (!mime) mime = strdup("unknown");

    /* Get file size */
    fsize = file_size(argv[1]);
    if (fsize < 0) fsize = 0;

    /* Extract text based on MIME type */
    if (mime && strcmp(mime, "application/pdf") == 0) {
        snprintf(cmd, sizeof(cmd), "pdftotext -layout \"%s\" - 2>/dev/null", argv[1]);
        extracted = read_cmd(cmd);
    } else if (mime && strncmp(mime, "image/", 6) == 0) {
        snprintf(cmd, sizeof(cmd), "tesseract \"%s\" stdout -l eng 2>/dev/null", argv[1]);
        extracted = read_cmd(cmd);
    }

    /* Fallback: try reading as text */
    if (!extracted) {
        FILE *f = fopen(argv[1], "r");
        if (f) {
            extracted = (char *)malloc(MAX_BUF);
            if (extracted) {
                size_t n = fread(extracted, 1, MAX_BUF - 1, f);
                extracted[n] = '\0';
            }
            fclose(f);
        }
    }

    /* Last resort: hex dump */
    if (!extracted) {
        FILE *f = fopen(argv[1], "rb");
        if (f) {
            unsigned char raw[256];
            size_t n = fread(raw, 1, sizeof(raw), f);
            fclose(f);
            extracted = (char *)malloc(n * 2 + 1);
            if (extracted) {
                size_t i;
                for (i = 0; i < n; i++)
                    snprintf(extracted + i*2, 3, "%02x", raw[i]);
            }
        }
    }

    escaped = json_escape(extracted ? extracted : "");

    /* Print JSON metadata */
    printf("{");
    printf("\"mime_type\":"); json_str(mime ? mime : "unknown");
    printf(",\"file_size_bytes\":%lld", fsize);
    printf(",\"extracted_text\":"); json_str(escaped ? escaped : "");
    printf("}\n");

    free(mime);
    free(extracted);
    free(escaped);
    return 0;
}
