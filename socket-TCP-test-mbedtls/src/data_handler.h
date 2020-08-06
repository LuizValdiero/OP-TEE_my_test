#ifndef DATA_HANDLER_H
#define DATA_HANDLER_H

#include <stdio.h>
#include <string.h>
#include <stdint.h>

#include "data_structure/record.h"
#include "data_structure/serie.h"

#include "defines.h"
#include "http_handler.h"

typedef struct data_handler_t {
    uint8_t data_code;
    int data_size;
    int (*mount_data_package)(buffer_t * out, int *displacement, void * data);
    int (*print_json)(buffer_t * out, int *displacement, void * data);
    path_t  request_path;
} data_handler_t;

typedef enum data_type_t {SERIE, RECORD} data_type_t;

// #define size_serie 41
// #define size_record 41
// #define size_smartdata 0

extern data_handler_t data_handler[];


typedef struct credentials_t
{
    const char * domain;
    const char * username;
    const char *  password;
} credentials_t;

int write_size_and_value(buffer_t * out, int *displacement, const char * value);

int credentials_print(buffer_t * out, int *displacement, struct credentials_t * credentials);
int credentials_print_json(buffer_t * out, int *displacement, struct credentials_t * credentials);

int create_data_package( data_type_t data_type, buffer_t * out, void * data);
int data_package_to_json(buffer_t * out, int *displacement, buffer_t * data);
int get_index_by_data_code(uint8_t data_code);
path_t get_request_path_of_data_package(buffer_t * data);

#endif // DATA_HANDLER_H
