#include <serial_package.h>

int mount_serial_package(TEE_Param * out, serial_header_t * header, buffer_t * data) {
    uint32_t header_size = sizeof(serial_header_t);

    if (out->memref.size < (header_size + data->buffer_size)) {
        return TEE_ERROR_SHORT_BUFFER;
    }
	memcpy(((unsigned char *) out->memref.buffer), header, header_size);
	memcpy(((unsigned char *) out->memref.buffer) + header_size, data->buffer, data->buffer_size);
    out->memref.size = header_size + data->buffer_size;

    return TEE_SUCCESS;
}

int dismount_serial_package(TEE_Param * in, serial_header_t * header, buffer_t * data) {
    memcpy(header, in->memref.buffer, sizeof(serial_header_t));
    int displacement = sizeof(serial_header_t);
    data->buffer = ((unsigned char *)       in->memref.buffer) + displacement;
    data->buffer_size = in->memref.size - displacement;

    if (data->buffer_size != header->encrypted_size)
        return TEE_ERROR_BAD_PARAMETERS;

    return TEE_SUCCESS;
}
