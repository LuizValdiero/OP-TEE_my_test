#include <data_structure/record.h>

int record_mount(buffer_t * out, int *displacement, void * data) {
    record_t * record = (record_t *) data;
    uint32_t size_record = sizeof(record_t);
    if (out->buffer_size < *displacement + size_record)
        return TEE_ERROR_SHORT_BUFFER;
    
    memcpy(out->buffer + *displacement, record, size_record);
    *displacement += size_record;
    return TEE_SUCCESS;
}

int record_print_json(buffer_t * out, int *displacement, void * data) {
    record_t * record = (record_t *) data;
    
    char * buffer = (char *) out->buffer + *displacement;
    int avaliable_size = out->buffer_size - *displacement;    
    int size_print = snprintf(buffer, avaliable_size, \
        "\"smartdata\": [{\"version\": \"%d.%d\", " \
        "\"unit\": %u, \"value\": ", \
        get_version_high(record->version), \
        get_version_low(record->version), \
        record->unit);

    buffer += size_print;
    avaliable_size -= size_print;
    int aux_size_print = snprintf_double(buffer, avaliable_size, record->value);

    size_print += aux_size_print;
    buffer += aux_size_print;
    avaliable_size -= aux_size_print;

    size_print += snprintf(buffer, avaliable_size, \
        ", \"confidence\": %u, \"error\": 0, " \
        "\"x\": %d, \"y\": %d, \"z\": %d, " \
        "\"t\": %llu, \"dev\": %u}]", \
        record->uncertainty, \
        record->x, record->y, record->z, \
        record->t, record->dev);

    if(avaliable_size < size_print)
        return TEE_ERROR_SHORT_BUFFER;

    *displacement += size_print;

    return TEE_SUCCESS;
}
