#ifndef DATA_HANDLER_H
#define DATA_HANDLER_H

#include <stdio.h>
#include <string.h>
#include <stdint.h>


typedef enum data_type_t {SERIE, RECORD} data_type_t;

#define size_serie 164
#define size_record 164
#define size_smartdata 0

extern const int size_data_list[];

struct __attribute__((__packed__)) Serie {
    uint8_t version;
    uint32_t unit;
    int32_t x;
    int32_t y;
    int32_t z;
    int32_t dev;
    uint32_t r;
    uint64_t t0;
    uint64_t t1;
};

struct __attribute__((__packed__)) Record {
    uint8_t version;
    uint32_t unit;
    double value;
    uint32_t uncertainty;
    int32_t x;
    int32_t y;
    int32_t z;
    uint32_t dev;
    uint64_t t;
};

struct Credentials
{
    const char * domain;
    const char * username;
    const char *  password;
};

int write_size_and_value(char * buffer, const char * value);
int get_version_high(uint8_t version);
int get_version_low(uint8_t version);

int credentials_print(char * buffer, struct Credentials * credentials);
int credentials_print_json(char * buffer, int size, struct Credentials * credentials);

int series_print(char * buffer, int size, void * data);
int series_print_json(char * buffer, int size, void * data);

int record_print(char * buffer, int size, void * data);
int record_print_json(char * buffer, int size, void * data);

#endif // DATA_HANDLER_H

/*
2.
    "series" : Object
    {
        "version" : unsigned char
        "unit" : unsigned long
        "x" : long
        "y" : long
        "z" : long
        "r" : unsigned long
        "t0" : unsigned long long
        "t1" : unsigned long long
    }
3. SmartData version 1.1
struct Series {
    unsigned char version;
    unsigned long unit;
    long x;
    long y;
    long z;
    unsigned long r;
    unsigned long long t0;
    unsigned long long t1;
}
*/

/*
2.
{
    "smartdata" : Array
    [
        {
            "version" : unsigned char
            "unit" : unsigned long
            "value" : double
            "uncertainty" : unsigned long
            "x" : long
            "y" : long
            "z" : long
            "t" : unsigned long long
            "dev" : unsigned long
        }
    ]
    "credentials" : Object
    {
        "domain" : string
        "username" : string
        "password" : string
    }    
}

3. SmartData version 1.1
struct SmartData {
    unsigned char version;
    unsigned long unit;
    double value;
    unsigned long uncertainty;
    long x;
    long y;
    long z;
    unsigned long dev;
    unsigned long long t;
}
*/
