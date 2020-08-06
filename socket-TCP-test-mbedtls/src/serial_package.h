#ifndef SERIAL_PACKAGE_H
#define SERIAL_PACKAGE_H

#include "defines.h"
#include <string.h>

typedef struct  __attribute__((__packed__)) serial_header_t {
    uint32_t encrypted_size;
    unsigned char iv[16];
} serial_header_t;

int mount_serial_package(buffer_t * out, serial_header_t * header, buffer_t * data);
int dismount_serial_package(buffer_t * in, serial_header_t * header, buffer_t * data);

#endif // SERIAL_PACKAGE_H