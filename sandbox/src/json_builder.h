/* Safe JSON string builder — zero external dependencies.
 *
 * Builds JSON objects incrementally with automatic buffer growth.
 * All strings are properly escaped for JSON safety (quotes, backslashes,
 * control characters). Uses bounded functions exclusively.
 */
#ifndef JSON_BUILDER_H
#define JSON_BUILDER_H

#include <stddef.h>

typedef struct {
    char  *buf;
    size_t len;    /* current used length (excluding NUL) */
    size_t cap;    /* allocated capacity */
    int    first;  /* 1 = no comma needed for next field */
} JsonBuf;

/* Initialise with at least `initial_cap` bytes. Returns 0 on success. */
int  json_init(JsonBuf *j, size_t initial_cap);

/* Free internal buffer. Safe to call multiple times. */
void json_free(JsonBuf *j);

/* Start/end a JSON object `{ ... }` */
void json_obj_open(JsonBuf *j);
void json_obj_close(JsonBuf *j);

/* Add a string field:  "key":"value"  (value is JSON-escaped) */
void json_add_str(JsonBuf *j, const char *key, const char *value);

/* Add an integer field:  "key":123  */
void json_add_int(JsonBuf *j, const char *key, long long value);

/* Add a boolean field:  "key":true / "key":false  */
void json_add_bool(JsonBuf *j, const char *key, int value);

/* Start a nested object for a key:  "key":{   */
void json_nested_open(JsonBuf *j, const char *key);

/* Close the innermost nested object:  }   */
void json_nested_close(JsonBuf *j);

/* Append raw pre-built JSON fragment (no escaping, no key). Use with care. */
void json_append_raw(JsonBuf *j, const char *raw);

/* Return the completed NUL-terminated JSON string. Owned by JsonBuf. */
const char *json_cstr(const JsonBuf *j);

#endif /* JSON_BUILDER_H */
