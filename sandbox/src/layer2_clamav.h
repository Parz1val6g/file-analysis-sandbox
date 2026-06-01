/* Layer 2: Static Antivirus Scan via ClamAV. */
#ifndef LAYER2_CLAMAV_H
#define LAYER2_CLAMAV_H

typedef struct {
    int    status;        /* 0=clean, 1=infected, 2=error */
    char   reason[512];
    char   virus_name[256];
} Layer2Result;

Layer2Result layer2_scan(const char *file_path);

#endif /* LAYER2_CLAMAV_H */
