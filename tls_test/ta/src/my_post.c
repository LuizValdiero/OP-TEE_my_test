#include "my_post.h"

int mount_body(char * buffer, int size, int (*print)(char *, int, void*), void * data, struct Credentials * credential) {
    int size_data = snprintf(buffer, size, "{");
    size_data += print(buffer + size_data, size-size_data, data);
    /*
    if(workflow) {
        printf(" \n size_data: %d", size_data);
        size_data = strrchr(buffer, '}') - buffer;
        size_data += sprintf(buffer+size_data, ", \"workflow\":%s}", workflow);
    }
    */
    if(credential) {
        size_data += credentials_print_json(buffer + size_data, size-size_data, credential);
    }
    size_data += snprintf(buffer + size_data,size-size_data, "}");
    return size_data;
}

int mount_request(char * buff, int size, struct HttpHeader_t * httpHeader, data_type_t data_type, void * data, struct Credentials * credentials) {
    char buffer_data[512];
    
    int size_data = 0;
    if(data_type == SERIE)
        size_data = mount_body(buffer_data, size, series_print_json, data, credentials);

    if(data_type == RECORD)
        size_data = mount_body(buffer_data, size, record_print_json, data, credentials);

    if (!size_data)
        return 0;

    printf("size_data: %d\n", size_data);

    httpHeader->content_length = size_data;
    int displacement = mount_http_header(buff, size, httpHeader);

    memcpy(buff+displacement, buffer_data, size_data);
    return displacement + size_data;
}
