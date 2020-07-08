
#include "data_handler.h"


data_handler_t data_handler[NUM_DATA_TYPE] = {
    {(unsigned char) 'S', sizeof(serie_t), serie_mount, serie_print_json},
    {(unsigned char) 'R', sizeof(record_t), record_mount, record_print_json}
};

int write_size_and_value(buffer_t * out, int *displacement, const char * value){
    const int byte_size = 1;
    int8_t value_size = strlen(value);
    if (value){
        memcpy(out->buffer + *displacement + byte_size, value, value_size);
    }
    memset(out->buffer + *displacement, value_size, 1);
    *displacement += value_size + byte_size;
    return TEE_SUCCESS;
}

int get_version_high(uint8_t version) {
    return (version & 0xf0)>>4;
}

int get_version_low(uint8_t version) {
    return version & 0x0f;
}

int credentials_print(buffer_t * out, int *displacement, struct credentials_t * credentials) {
    write_size_and_value(out, displacement, credentials->domain);
    write_size_and_value(out, displacement, credentials->username);
    write_size_and_value(out, displacement, credentials->password);
    return TEE_SUCCESS;
}

int credentials_print_json(buffer_t * out, int *displacement, struct credentials_t * credentials)
{
    char * buffer = (char *) out->buffer + *displacement;
    int avaliable_size = out->buffer_size - *displacement;

    int credential_size = snprintf(buffer, avaliable_size, ", \"credentials\": { \"domain\":\"%s\"," \
        " \"username\":\"%s\", \"password\":\"%s\"}", \
        credentials->domain, credentials->username, credentials->password);

    if(avaliable_size < credential_size)
        return TEE_ERROR_SHORT_BUFFER;

    *displacement += credential_size;
    return TEE_SUCCESS;
}

int create_data_package( data_type_t data_type, buffer_t * out, void * data) {
    int num_types = sizeof(data_handler);    
    if((data_type < 0) && ( data_type >= num_types))
        return TEE_ERROR_NOT_IMPLEMENTED;
    
    struct data_handler_t data_struct = data_handler[data_type];

    out->buffer_size = data_struct.data_size + 1;
    out->buffer = TEE_Malloc(out->buffer_size, 0);
    if (!out->buffer)
        return TEE_ERROR_OUT_OF_MEMORY;
    
    memset(out->buffer, data_struct.data_code, 1);
    int displacement = 1;
    return data_struct.mount_data_package(out, &displacement, data);
}

int data_package_to_json(buffer_t * out, int *displacement, buffer_t * data) {
    int num_types = sizeof(data_handler);
    uint8_t data_code = data->buffer[0];
    int i = 0;
    for (; (i < num_types) && (data_handler[i].data_code != data_code); i++);

    if( i >= num_types)
        return TEE_ERROR_NOT_IMPLEMENTED;
    int res = data_handler[i].print_json(out, displacement, (void *) (data->buffer + 1));
    return res;
}

int serie_mount(buffer_t * out, int *displacement, void * data) {
    serie_t * serie = (serie_t *) data;
    uint32_t size_serie = sizeof(serie_t);
    if (out->buffer_size < *displacement + size_serie)
        return TEE_ERROR_SHORT_BUFFER;
    
    memcpy(out->buffer + *displacement, serie, size_serie);
    
    *displacement += size_serie;
    return TEE_SUCCESS;
}

int serie_print_json(buffer_t * out, int *displacement, void * data) {
    serie_t * serie = (serie_t *) data;
    
    char * buffer = (char *) out->buffer + *displacement;
    int avaliable_size = out->buffer_size - *displacement;
    
    int size_print = snprintf(buffer, avaliable_size, \
        "\"series\": {\"version\": \"%d.%d\", " \
        "\"unit\": %u, \"x\": %d, \"y\": %d, \"z\": %d, " \
        "\"dev\": %d,  \"r\": %u, " \
        " \"t0\": %llu, \"t1\": %llu}", \
        get_version_high(serie->version), get_version_low(serie->version), \
        serie->unit, serie->x, serie->y, serie->z, \
        serie->dev, serie->r, \
        serie->t0, serie->t1);
    
    if(avaliable_size < size_print)
        return TEE_ERROR_SHORT_BUFFER;

    *displacement += size_print;

    return TEE_SUCCESS;
}


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
        "\"unit\": %u, \"value\": %f, \"uncertainty\": %u, "\
        "\"x\": %d, \"y\": %d, \"z\": %d, " \
        "\"t\": %llu, \"dev\": %d}]", \
        get_version_high(record->version), get_version_low(record->version), \
        record->unit, record->value, record->uncertainty, \
        record->x, record->y, record->z, \
        record->t, record->dev);
    
    if(avaliable_size < size_print)
        return TEE_ERROR_SHORT_BUFFER;

    *displacement += size_print;

    return TEE_SUCCESS;
}
