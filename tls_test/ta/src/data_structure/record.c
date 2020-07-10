#include <data_structure/record.h>
#include <utils/double_format_handler.h>

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
        "\"unit\": %u, \"value\": %d, " \
        "\"confidence\": %u, \"error\": 0, " \
        "\"x\": %d, \"y\": %d, \"z\": %d, " \
        "\"t\": %llu, \"dev\": %u}]", \
        get_version_high(record->version), get_version_low(record->version), \
        record->unit, get_integer_of_double(record->value), \
        record->uncertainty, \
        record->x, record->y, record->z, \
        record->t, record->dev);
    DMSG("\n    * value: %d",  get_integer_of_double(record->value));
    if(avaliable_size < size_print)
        return TEE_ERROR_SHORT_BUFFER;

    *displacement += size_print;

    return TEE_SUCCESS;
}
