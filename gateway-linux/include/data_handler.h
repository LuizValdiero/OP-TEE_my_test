#ifndef DATA_HANDLER_H
#define DATA_HANDLER_H

#include <stdio.h>
#include <string.h>
#include <stdint.h>

#include "data_structure/record.h"
#include "data_structure/serie.h"

#include "defines.h"

typedef struct data_handler_t {
    uint8_t data_code;
    int data_size;
    int (*mount_data_package)(buffer_t * out, int *displacement, void * data);
    int (*print_json)(buffer_t * out, int *displacement, void * data);
} data_handler_t;

typedef enum data_type_t {SERIE, RECORD} data_type_t;

extern data_handler_t data_handler[];

int create_data_package( data_type_t data_type, buffer_t * out, void * data);

#endif // DATA_HANDLER_H
