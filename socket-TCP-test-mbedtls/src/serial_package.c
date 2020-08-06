#include "serial_package.h"

int mount_serial_package(buffer_t * out, serial_header_t * header, buffer_t * data) {
    uint32_t header_size = sizeof(serial_header_t);

    if (out->buffer_size < (header_size + data->buffer_size)) {
        return 1;//TEE_ERROR_SHORT_BUFFER;
    }
	memcpy(((unsigned char *) out->buffer), header, header_size);
	memcpy(((unsigned char *) out->buffer) + header_size, data->buffer, data->buffer_size);
    out->buffer_size = header_size + data->buffer_size;
    return 0;
}

int dismount_serial_package(buffer_t * in, serial_header_t * header, buffer_t * data) {
    memcpy(header, in->buffer, sizeof(serial_header_t));
    int displacement = sizeof(serial_header_t);
    data->buffer = ((unsigned char *) in->buffer) + displacement;
    data->buffer_size = in->buffer_size - displacement;

    if (data->buffer_size != header->encrypted_size)
        return 1;//TEE_ERROR_BAD_PARAMETERS;

    return 0;
}
