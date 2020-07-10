#ifndef SERIE_H
#define SERIE_H

#include <string.h>

#include <defines.h>
#include <utils/data_version_handler.h>

typedef struct __attribute__((__packed__)) {
    uint8_t version;
    uint32_t unit;
    int32_t x;
    int32_t y;
    int32_t z;
    uint32_t dev;
    uint32_t r;
    uint64_t t0;
    uint64_t t1;
} serie_t;

int serie_mount(buffer_t * out, int *displacement, void * data);
int serie_print_json(buffer_t * out, int *displacement, void * data);


#endif // SERIE_H