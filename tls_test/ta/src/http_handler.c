#include "http_handler.h"


const char * method_list[] = { "GET", "POST", "PUT", NULL };
const char * path_list[] = { \
    "/api/get.php", \
    "/api/put.php", \
    "/api/attach.php", \
    NULL \
};
const char * content_type_list[] = { \
    "application/json", \
    "application/octet-stream", \
    NULL
};

int mount_http_header(buffer_t * out, int *displacement, struct HttpHeader_t * httpHeader) {
    char * buffer = (char *) out->buffer + *displacement;
    int avaliable_size = out->buffer_size - *displacement;
    
    int size_print = snprintf(buffer, avaliable_size, \
                "%s %s HTTP/1.1\r\n" \
                "Host: %s\r\n" \
                "Content-Length: %d\r\n" \
                "Content-Type: %s\r\n"\
                "Connection: close \r\n\r\n", \
                method_list[httpHeader->method], \
                path_list[httpHeader->path], \
                httpHeader->hostname, \
                httpHeader->content_length, \
                content_type_list[httpHeader->content_type]);

    if(avaliable_size < size_print)
        return TEE_ERROR_SHORT_BUFFER;

    *displacement += size_print;

    return TEE_SUCCESS;
}
