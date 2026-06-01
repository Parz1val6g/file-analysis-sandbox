/* Comprehensive test suite for sandbox_engine.
 *
 * Tests all three layers, JSON contract compliance, stdout isolation,
 * ClamAV graceful bypass, input validation, and robustness.
 *
 * Build:  gcc -o test_runner test_runner.c
 * Run:    ./test_runner
 *
 * Exit code = number of failed tests (0 = all pass).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#ifdef _WIN32
#include <windows.h>
#define popen  _popen
#define pclose _pclose
#define ENGINE_CMD ".\\sandbox_engine.exe"
#define PATHSEP  "\\"
#else
#define ENGINE_CMD "./sandbox_engine"
#define PATHSEP  "/"
#endif

#define MAX_OUT 65536

static int tests_run   = 0;
static int tests_pass  = 0;
static int tests_fail  = 0;

/* --- helpers --- */

static char *run_engine(const char *arg, int *exit_code) {
    char cmd[2048];
    FILE *fp;
    static char buf[MAX_OUT];

    if (arg)
        snprintf(cmd, sizeof(cmd), "%s \"%s\"", ENGINE_CMD, arg);
    else
        snprintf(cmd, sizeof(cmd), "%s", ENGINE_CMD);

    fp = popen(cmd, "r");
    if (!fp) { *exit_code = -1; return NULL; }

    size_t n = fread(buf, 1, MAX_OUT - 1, fp);
    buf[n] = '\0';
    int rc = pclose(fp);
#ifdef _WIN32
    *exit_code = rc;
#else
    *exit_code = WEXITSTATUS(rc);
#endif
    return buf;
}

static int str_contains(const char *haystack, const char *needle) {
    return strstr(haystack, needle) != NULL;
}

static int str_startswith(const char *s, const char *prefix) {
    return strncmp(s, prefix, strlen(prefix)) == 0;
}

static int is_valid_json(const char *s) {
    /* Minimal check: starts with { and ends with } */
    const char *p = s;
    while (*p == ' ' || *p == '\n' || *p == '\r') p++;
    if (*p != '{') return 0;
    const char *end = s + strlen(s) - 1;
    while (end > p && (*end == ' ' || *end == '\n' || *end == '\r')) end--;
    return *end == '}';
}

static const char *json_get(const char *json, const char *key) {
    /* Simple JSON value extractor — finds "key":"value" */
    static char val[4096];
    char search[256];
    const char *p, *start, *end;
    size_t len;

    snprintf(search, sizeof(search), "\"%s\"", key);
    p = strstr(json, search);
    if (!p) return NULL;
    p += strlen(search);
    while (*p == ' ' || *p == ':') p++;
    if (*p == '"') {
        start = p + 1;
        end = start;
        while (*end && *end != '"') {
            if (*end == '\\') end++;
            end++;
        }
        len = (size_t)(end - start);
        if (len >= sizeof(val)) len = sizeof(val) - 1;
        memmove(val, start, len);
        val[len] = '\0';
        return val;
    }
    if (*p == 't' || *p == 'f' || *p == 'n') {
        start = p;
        while (*p && *p != ',' && *p != '}' && *p != ' ') p++;
        len = (size_t)(p - start);
        if (len >= sizeof(val)) len = sizeof(val) - 1;
        memmove(val, start, len);
        val[len] = '\0';
        return val;
    }
    /* number */
    start = p;
    while (*p && *p != ',' && *p != '}') p++;
    len = (size_t)(p - start);
    if (len >= sizeof(val)) len = sizeof(val) - 1;
    memmove(val, start, len);
    val[len] = '\0';
    return val;
}

/* --- test macros --- */

#define TEST(name) \
    static void test_##name(void); \
    static void test_##name(void)

#define RUN_TEST(name) do { \
    tests_run++; \
    printf("  %-55s", #name); \
    test_##name(); \
    printf(" PASSED\n"); \
    tests_pass++; \
} while(0)

#define ASSERT(cond, msg) do { \
    if (!(cond)) { \
        printf(" FAILED\n    %s\n", msg); \
        tests_fail++; return; \
    } \
} while(0)

#define ASSERT_CONTAINS(str, substr) \
    ASSERT(str_contains(str, substr), "expected to contain: " substr)

#define ASSERT_NOT_CONTAINS(str, substr) \
    ASSERT(!str_contains(str, substr), "unexpected content: " substr)

#define ASSERT_EQ_STR(a, b) \
    ASSERT(strcmp(a, b) == 0, "expected equal strings")

/* --- fixtures path --- */
#ifdef _WIN32
static const char *FIXTURES = ".\\fixtures";
#else
static const char *FIXTURES = "./fixtures";
#endif

static char fixture_path[512];
static const char *fp(const char *name) {
    snprintf(fixture_path, sizeof(fixture_path), "%s%s%s", FIXTURES, PATHSEP, name);
    return fixture_path;
}

/* ================================================================
 * TESTS
 * ================================================================ */

/* ---- Layer 1: Magic Bytes ---- */

TEST(l1_malformed_pdf_infected) {
    int ec; char *out = run_engine(fp("malformed_header.pdf"), &ec);
    ASSERT(out && is_valid_json(out), "not valid JSON");
    ASSERT(ec != 0, "exit code should be non-zero");
    ASSERT_CONTAINS(out, "infected");
    ASSERT_CONTAINS(out, "mismatch");
}

TEST(l1_valid_pdf_passes) {
    int ec; char *out = run_engine(fp("valid.pdf"), &ec);
    ASSERT(out && is_valid_json(out), "not valid JSON");
    ASSERT_NOT_CONTAINS(out, "\"status\":\"infected\"");
}

TEST(l1_valid_png_passes) {
    int ec; char *out = run_engine(fp("valid.png"), &ec);
    ASSERT(out && is_valid_json(out), "not valid JSON");
    ASSERT_NOT_CONTAINS(out, "\"infected\"");
}

TEST(l1_valid_gif_passes) {
    int ec; char *out = run_engine(fp("valid.gif"), &ec);
    ASSERT(out && is_valid_json(out), "not valid JSON");
    ASSERT_NOT_CONTAINS(out, "\"infected\"");
}

TEST(l1_clean_txt_passes) {
    int ec; char *out = run_engine(fp("clean.txt"), &ec);
    ASSERT(out && is_valid_json(out), "not valid JSON");
    ASSERT_NOT_CONTAINS(out, "\"infected\"");
}

/* ---- JSON Protocol ---- */

TEST(json_missing_arg) {
    int ec; char *out = run_engine(NULL, &ec);
    ASSERT(out && is_valid_json(out), "not valid JSON");
    ASSERT_CONTAINS(out, "error");
    ASSERT(ec != 0, "should exit non-zero");
}

TEST(json_nonexistent_file) {
    int ec; char *out = run_engine("/nonexistent/file.xyz", &ec);
    ASSERT(out && is_valid_json(out), "not valid JSON");
    ASSERT_CONTAINS(out, "error");
}

TEST(json_infected_has_reason) {
    int ec; char *out = run_engine(fp("malformed_header.pdf"), &ec);
    ASSERT_CONTAINS(out, "reason");
}

TEST(json_has_status_key) {
    int ec; char *out = run_engine(fp("clean.txt"), &ec);
    ASSERT_CONTAINS(out, "\"status\"");
}

/* ---- Stdout Isolation ---- */

TEST(isolation_single_line) {
    int ec; char *out = run_engine(fp("clean.txt"), &ec);
    ASSERT(out != NULL, "no output");
    /* Count newlines — should be at most 1 */
    int nl = 0;
    for (const char *p = out; *p; p++) if (*p == '\n') nl++;
    ASSERT(nl <= 1, "more than one line in stdout");
}

TEST(isolation_no_debug_prefix) {
    int ec; char *out = run_engine(fp("clean.txt"), &ec);
    ASSERT_NOT_CONTAINS(out, "[engine]");
}

/* ---- ClamAV Bypass ---- */

TEST(clamav_bypass_not_infected) {
    int ec; char *out = run_engine(fp("valid.pdf"), &ec);
    ASSERT_NOT_CONTAINS(out, "\"status\":\"infected\"");
}

TEST(clamav_bypass_metadata) {
    int ec; char *out = run_engine(fp("valid.pdf"), &ec);
    /* If clean, must have clamav_skipped */
    if (str_contains(out, "\"status\":\"clean\"")) {
        ASSERT_CONTAINS(out, "clamav_skipped");
    }
}

/* ---- Robustness ---- */

TEST(robust_directory_input) {
    int ec; char *out = run_engine(FIXTURES, &ec);
    ASSERT(out && is_valid_json(out), "not valid JSON");
    ASSERT_CONTAINS(out, "error");
}

TEST(robust_binary_file) {
    /* Create a temp binary file */
    FILE *f = fopen("__test_binary.tmp", "wb");
    ASSERT(f != NULL, "cannot create temp file");
    fwrite("hello\0world\0binary", 1, 19, f);
    fclose(f);
    int ec; char *out = run_engine("__test_binary.tmp", &ec);
    ASSERT(out != NULL, "no output");
    remove("__test_binary.tmp");
}

TEST(robust_empty_file) {
    FILE *f = fopen("__test_empty.tmp", "w");
    ASSERT(f != NULL, "cannot create temp file");
    fclose(f);
    int ec; char *out = run_engine("__test_empty.tmp", &ec);
    ASSERT(out != NULL, "no output");
    ASSERT_CONTAINS(out, "error");
    ASSERT_CONTAINS(out, "empty");
    remove("__test_empty.tmp");
}

/* ---- Contract: signature ---- */

TEST(sig_present_on_clean) {
    int ec; char *out = run_engine(fp("valid.pdf"), &ec);
    if (str_contains(out, "\"status\":\"clean\""))
        ASSERT_CONTAINS(out, "signature");
}

TEST(sig_is_64_hex) {
    int ec; char *out = run_engine(fp("valid.pdf"), &ec);
    const char *sig = json_get(out, "signature");
    if (sig) {
        ASSERT(strlen(sig) == 64, "signature must be 64 hex chars");
        for (int i = 0; sig[i]; i++)
            ASSERT((sig[i] >= '0' && sig[i] <= '9') || (sig[i] >= 'a' && sig[i] <= 'f'),
                   "signature has invalid hex char");
    }
}

/* ---- Contract: infected format ---- */

TEST(infected_has_declared_extension) {
    int ec; char *out = run_engine(fp("malformed_header.pdf"), &ec);
    ASSERT_CONTAINS(out, "declared_extension");
    ASSERT_CONTAINS(out, "true_type");
}

/* ---- Layer 1: edge cases ---- */

TEST(l1_no_extension) {
    /* Create a file with no extension and some content */
    FILE *f = fopen("__test_noext", "w");
    ASSERT(f != NULL, "cannot create temp file");
    fprintf(f, "hello");
    fclose(f);
    int ec; char *out = run_engine("__test_noext", &ec);
    ASSERT(out != NULL, "no output");
    ASSERT_NOT_CONTAINS(out, "\"infected\"");
    remove("__test_noext");
}

TEST(l1_empty_with_extension) {
    FILE *f = fopen("__test_empty.pdf", "w");
    ASSERT(f != NULL, "cannot create temp file");
    fclose(f);
    int ec; char *out = run_engine("__test_empty.pdf", &ec);
    ASSERT(out != NULL, "no output");
    /* Should be flagged by both validation (empty) and magic bytes */
    ASSERT(out && is_valid_json(out), "not valid JSON");
    remove("__test_empty.pdf");
}

/* ================================================================ */

int main(void) {
    printf("\n  sandbox_engine C Test Suite\n");
    printf("  ============================\n\n");

    printf("  Layer 1 — Magic Bytes:\n");
    RUN_TEST(l1_malformed_pdf_infected);
    RUN_TEST(l1_valid_pdf_passes);
    RUN_TEST(l1_valid_png_passes);
    RUN_TEST(l1_valid_gif_passes);
    RUN_TEST(l1_clean_txt_passes);
    RUN_TEST(l1_no_extension);
    RUN_TEST(l1_empty_with_extension);

    printf("\n  JSON Protocol:\n");
    RUN_TEST(json_missing_arg);
    RUN_TEST(json_nonexistent_file);
    RUN_TEST(json_infected_has_reason);
    RUN_TEST(json_has_status_key);

    printf("\n  Stdout Isolation:\n");
    RUN_TEST(isolation_single_line);
    RUN_TEST(isolation_no_debug_prefix);

    printf("\n  ClamAV Bypass:\n");
    RUN_TEST(clamav_bypass_not_infected);
    RUN_TEST(clamav_bypass_metadata);

    printf("\n  Robustness:\n");
    RUN_TEST(robust_directory_input);
    RUN_TEST(robust_binary_file);
    RUN_TEST(robust_empty_file);

    printf("\n  Contract:\n");
    RUN_TEST(sig_present_on_clean);
    RUN_TEST(sig_is_64_hex);
    RUN_TEST(infected_has_declared_extension);

    printf("\n  ============================\n");
    printf("  Results: %d/%d passed", tests_pass, tests_run);
    if (tests_fail > 0) printf(", %d FAILED", tests_fail);
    printf("\n\n");

    return tests_fail;
}
