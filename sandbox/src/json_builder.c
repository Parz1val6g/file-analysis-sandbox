/* Safe JSON string builder — zero external dependencies.
 *
 * Grows buffer automatically. All strings are JSON-escaped to prevent
 * injection. Uses snprintf and bounded memmove exclusively.
 */
#include "json_builder.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>

#define JSON_MIN_CAP 256

static int json_grow(JsonBuf *j, size_t needed) {
    size_t new_cap;
    char *new_buf;

    if (j->cap - j->len > needed) return 0;
    /* Guard against size_t wraparound in the doubling loop */
    if (j->cap > (size_t)-1 / 2) return -1;
    new_cap = j->cap ? j->cap * 2 : JSON_MIN_CAP;
    while (new_cap - j->len <= needed) {
        if (new_cap > (size_t)-1 / 2) return -1;
        new_cap *= 2;
    }
    new_buf = (char *)realloc(j->buf, new_cap);
    if (!new_buf) return -1;
    j->buf = new_buf;
    j->cap = new_cap;
    return 0;
}

int json_init(JsonBuf *j, size_t initial_cap) {
    if (initial_cap < JSON_MIN_CAP) initial_cap = JSON_MIN_CAP;
    j->buf = (char *)malloc(initial_cap);
    if (!j->buf) return -1;
    j->buf[0] = '\0';
    j->len = 0;
    j->cap = initial_cap;
    j->first = 1;
    return 0;
}

void json_free(JsonBuf *j) {
    free(j->buf);
    j->buf = NULL;
    j->len = 0;
    j->cap = 0;
    j->first = 1;
}

static void json_escape_and_append(JsonBuf *j, const char *value) {
    /* Write opening quote */
    if (json_grow(j, 2) == -1) return;
    j->buf[j->len++] = '"';

    while (*value) {
        char esc[8];
        int esc_len = 0;
        unsigned char c = (unsigned char)*value;

        switch (c) {
        case '"':  esc[0]='\\'; esc[1]='"';  esc_len=2; break;
        case '\\': esc[0]='\\'; esc[1]='\\'; esc_len=2; break;
        case '\b': esc[0]='\\'; esc[1]='b';  esc_len=2; break;
        case '\f': esc[0]='\\'; esc[1]='f';  esc_len=2; break;
        case '\n': esc[0]='\\'; esc[1]='n';  esc_len=2; break;
        case '\r': esc[0]='\\'; esc[1]='r';  esc_len=2; break;
        case '\t': esc[0]='\\'; esc[1]='t';  esc_len=2; break;
        default:
            if (c < 0x20) {
                /* \u00XX for control chars */
                esc_len = snprintf(esc, sizeof(esc), "\\u%04x", c);
            } else {
                esc[0] = c; esc_len = 1;
            }
            break;
        }

        if (json_grow(j, (size_t)esc_len) == -1) return;
        memmove(j->buf + j->len, esc, (size_t)esc_len);
        j->len += (size_t)esc_len;
        value++;
    }

    /* Closing quote */
    if (json_grow(j, 1) == -1) return;
    j->buf[j->len++] = '"';
    j->buf[j->len] = '\0';
}

static void json_comma(JsonBuf *j) {
    if (!j->first) {
        if (json_grow(j, 2) == -1) return;
        j->buf[j->len++] = ',';
    }
    j->first = 0;
}

void json_obj_open(JsonBuf *j) {
    json_grow(j, 1);
    j->buf[j->len++] = '{';
    j->buf[j->len] = '\0';
    j->first = 1;
}

void json_obj_close(JsonBuf *j) {
    json_grow(j, 1);
    j->buf[j->len++] = '}';
    j->buf[j->len] = '\0';
}

void json_add_str(JsonBuf *j, const char *key, const char *value) {
    json_comma(j);
    /* key */
    json_escape_and_append(j, key);
    json_grow(j, 1);
    j->buf[j->len++] = ':';
    /* value */
    json_escape_and_append(j, value);
    j->buf[j->len] = '\0';
}

void json_add_int(JsonBuf *j, const char *key, long long value) {
    char num[32];
    int n = snprintf(num, sizeof(num), "%" PRId64, (int64_t)value);
    json_comma(j);
    json_escape_and_append(j, key);
    json_grow(j, (size_t)n + 2);
    j->buf[j->len++] = ':';
    memmove(j->buf + j->len, num, (size_t)n);
    j->len += (size_t)n;
    j->buf[j->len] = '\0';
}

void json_add_bool(JsonBuf *j, const char *key, int value) {
    const char *b = value ? "true" : "false";
    size_t blen = value ? 4 : 5;
    json_comma(j);
    json_escape_and_append(j, key);
    json_grow(j, blen + 1);
    j->buf[j->len++] = ':';
    memmove(j->buf + j->len, b, blen);
    j->len += blen;
    j->buf[j->len] = '\0';
}

void json_nested_open(JsonBuf *j, const char *key) {
    json_comma(j);
    json_escape_and_append(j, key);
    json_grow(j, 2);
    j->buf[j->len++] = ':';
    j->buf[j->len++] = '{';
    j->buf[j->len] = '\0';
    j->first = 1;
}

void json_nested_close(JsonBuf *j) {
    json_grow(j, 1);
    j->buf[j->len++] = '}';
    j->buf[j->len] = '\0';
    j->first = 0;
}

void json_append_raw(JsonBuf *j, const char *raw) {
    size_t rlen = strlen(raw);
    json_comma(j);
    json_grow(j, rlen);
    memmove(j->buf + j->len, raw, rlen);
    j->len += rlen;
    j->buf[j->len] = '\0';
}

const char *json_cstr(const JsonBuf *j) {
    return j->buf ? j->buf : "";
}
