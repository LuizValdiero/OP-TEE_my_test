#ifndef RECORD_H
#define RECORD_H

#include <string.h>

#include <defines.h>
#include <utils/data_version_handler.h>
#include <utils/double_format_handler.h>

typedef struct __attribute__((__packed__)) {
    uint8_t version;
    uint32_t unit;
    double value;
    uint32_t uncertainty;
    int32_t x;
    int32_t y;
    int32_t z;
    uint32_t dev;
    uint64_t t;
} record_t;

int record_mount(buffer_t * out, int *displacement, void * data);
int record_print_json(buffer_t * out, int *displacement, void * data);

#endif // RECORD_H