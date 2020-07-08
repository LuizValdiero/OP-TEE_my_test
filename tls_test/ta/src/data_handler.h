#ifndef DATA_HANDLER_H
#define DATA_HANDLER_H

#include <stdio.h>
#include <string.h>
#include <stdint.h>

#include "defines.h"

typedef enum data_type_t { SERIE, RECORD } data_type_t;
//typedef int (*data_to_json)(buffer_t * out, int *displacement, void * data);

typedef struct data_handler_t {
    uint8_t data_code;
    int data_size;
    int (*mount_data_package)(buffer_t * out, int *displacement, void * data);
    int (*print_json)(buffer_t * out, int *displacement, void * data);
} data_handler_t;

typedef struct __attribute__((__packed__)) {
    uint8_t version;
    uint32_t unit;
    int32_t x;
    int32_t y;
    int32_t z;
    int32_t dev;
    uint32_t r;
    uint64_t t0;
    uint64_t t1;
} serie_t;

typedef struct __attribute__((__packed__)) {
    uint8_t version;
    uint32_t unit;
    double value;
    uint32_t uncertainty;
    int32_t x;
    int32_t y;
    int32_t z;
    uint32_t dev;
    uint64_t t;
} record_t;

typedef struct credentials_t
{
    const char * domain;
    const char * username;
    const char *  password;
} credentials_t;

int write_size_and_value(buffer_t * out, int *displacement, const char * value);
int get_version_high(uint8_t version);
int get_version_low(uint8_t version);

int credentials_print(buffer_t * out, int *displacement, struct credentials_t * credentials);
int credentials_print_json(buffer_t * out, int *displacement, struct credentials_t * credentials);

int create_data_package( data_type_t data_type, buffer_t * out, void * data);
int data_package_to_json(buffer_t * out, int *displacement, buffer_t * data);

int serie_mount(buffer_t * out, int *displacement, void * data);
int serie_print_json(buffer_t * out, int *displacement, void * data);

int record_mount(buffer_t * out, int *displacement, void * data);
int record_print_json(buffer_t * out, int *displacement, void * data);


#define NUM_DATA_TYPE 2
extern data_handler_t data_handler[NUM_DATA_TYPE];

#endif // DATA_HANDLER_H