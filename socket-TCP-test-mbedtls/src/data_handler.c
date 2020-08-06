
#include "data_handler.h"


data_handler_t data_handler[] = {
    {(unsigned char) 'S', sizeof(serie_t), serie_mount, serie_print_json, API_GET},
    {(unsigned char) 'R', sizeof(record_t), record_mount, record_print_json, API_PUT}
};

int write_size_and_value(buffer_t * out, int *displacement, const char * value){
    const int byte_size = 1;
    int8_t value_size = strlen(value);
    if (value){
        memcpy(out->buffer + *displacement + byte_size, value, value_size);
    }
    memset(out->buffer + *displacement, value_size, 1);
    *displacement += value_size + byte_size;
    return CODE_SUCCESS;
}

int credentials_print(buffer_t * out, int *displacement, struct credentials_t * credentials) {
    write_size_and_value(out, displacement, credentials->domain);
    write_size_and_value(out, displacement, credentials->username);
    write_size_and_value(out, displacement, credentials->password);
    return CODE_SUCCESS;
}

int credentials_print_json(buffer_t * out, int *displacement, struct credentials_t * credentials)
{
    char * buffer = (char *) out->buffer + *displacement;
    int avaliable_size = out->buffer_size - *displacement;

    int credential_size = snprintf(buffer, avaliable_size, ", \"credentials\": { \"domain\":\"%s\"," \
        " \"username\":\"%s\", \"password\":\"%s\"}", \
        credentials->domain, credentials->username, credentials->password);

    if(avaliable_size < credential_size)
        return CODE_ERROR_SHORT_BUFFER;

    *displacement += credential_size;
    return CODE_SUCCESS;
}

int create_data_package( data_type_t data_type, buffer_t * out, void * data) {
    int num_types = sizeof(data_handler);    
    if((data_type < 0) && ( data_type >= num_types))
        return CODE_ERROR_NOT_IMPLEMENTED;
    
    struct data_handler_t data_struct = data_handler[data_type];

    out->buffer_size = data_struct.data_size + 1;
    out->buffer = malloc(out->buffer_size);
    if (!out->buffer)
        return CODE_ERROR_OUT_OF_MEMORY;
    
    memset(out->buffer, data_struct.data_code, 1);
    int displacement = 1;
    return data_struct.mount_data_package(out, &displacement, data);
}

int data_package_to_json(buffer_t * out, int *displacement, buffer_t * data) {
    uint8_t data_code = data->buffer[0];
    int index_data_structure = get_index_by_data_code(data_code);
    if ( index_data_structure < 0)
        return CODE_ERROR_NOT_IMPLEMENTED;
    return data_handler[index_data_structure]\
            .print_json(out, displacement, (void *) (data->buffer + 1));
}

int get_index_by_data_code(uint8_t data_code) {
    int num_types = sizeof(data_handler);
    int i = 0;
    for (; (i < num_types) && (data_handler[i].data_code != data_code); i++);
    if ( i >= num_types)
        return -1;
    return i;
}

path_t get_request_path_of_data_package(buffer_t * data) {
    uint8_t data_code = *data->buffer;
    int data_structure_id = get_index_by_data_code(data_code);
    if (data_structure_id < 0)
        return -1;
    return data_handler[data_structure_id].request_path;
}
