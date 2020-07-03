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

int mount_http_header(char * buff, int size, struct HttpHeader_t * httpHeader) {
    return snprintf(buff, size, \
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
}