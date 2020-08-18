#include <http_handler.h>


const char * method_list[] = { "GET", "POST", "PUT", NULL };
const char * path_list[] = { \
    "/api/get.php", \
    "/api/put.php", \
    "/api/create.php", \
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
        return CODE_ERROR_SHORT_BUFFER;

    *displacement += size_print;

    return CODE_SUCCESS;
}

unsigned long get_response_code(buffer_t * response) {
    char * ptr_response = strstr((const char*) response->buffer, "HTTP/");
    if (ptr_response) {
        ptr_response = strchr(ptr_response, ' ');
        char * end_ptr;
        return strtoul((const char *) ptr_response, &end_ptr,0);
    }
    return 0;
}

void set_request_path_in_header(struct HttpHeader_t * httpHeader, path_t path) {
    httpHeader->path = path;
}