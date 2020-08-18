#ifndef _DECRYPT_H
#define _DECRYPT_H

#include <stdlib.h>

#include "data_handler.h"

/*
struct Package_t {
    data_type_t data_type;
    void * data;
};
*/

int alloc_and_mount_package(void ** package, char char_type, void * data, int data_size) {
    const int char_type_size = 1;
    *package = malloc(data_size + char_type_size);
    memcpy(*package, &char_type, char_type_size);
    memcpy((*package)+char_type_size, data, data_size);
    return char_type_size + data_size;
}

int create_package(void ** package, data_type_t type, void * data) {
    if (type == SERIE) {
        int size_data = sizeof(struct Serie);
        return alloc_and_mount_package(package, 'S', data, size_data);
    }
    if (type == RECORD) {
        int size_data = sizeof(struct Record);
        return alloc_and_mount_package(package, 'R', data, size_data);
    }
    return 0;
}

struct encrypted_package_t {
    uint16_t len;
    void * encrypted_package;
};

int encrypt_package(struct encrypted_package_t * encrypted_package,  void ** data, int size_data) {
    encrypted_package->len = size_data;
    encrypted_package->encrypted_package = *data;
    return encrypted_package->len;
}

void free_package(void * package) {
    if(package)
        free(package);    
}


#endif // _DECRYPT_H