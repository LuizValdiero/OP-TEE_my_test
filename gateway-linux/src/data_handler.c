
#include <data_handler.h>


data_handler_t data_handler[] = {
    {(unsigned char) 'S', sizeof(serie_t), serie_mount, serie_print_json},
    {(unsigned char) 'R', sizeof(record_t), record_mount, record_print_json}
};

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
