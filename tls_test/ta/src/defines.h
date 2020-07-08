
#ifndef DEFINES_H
#define DEFINES_H

#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>

#include <stdint.h>

typedef struct buffer_t {
    uint32_t buffer_size;
    unsigned char * buffer;
} buffer_t;

#endif // DEFINES_H