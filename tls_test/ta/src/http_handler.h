#ifndef HTTP_HANDLER_H
#define HTTP_HANDLER_H

#include <stdio.h>
#include <string.h>

#include "defines.h"

typedef enum method_t { GET,POST, PUT} method_t;
typedef enum path_t { API_GET, API_POST, API_ATTACH} path_t;
typedef enum content_type_t { JSON, OCTET_STREAM} content_type_t;

extern const char * method_list[];
extern const char * path_list[];
extern const char * content_type_list[];


struct HttpHeader_t {
    method_t method;
    path_t path;
    content_type_t content_type;
    const char * hostname;
    int content_length;
};

int mount_http_header(buffer_t * out, int *displacement, struct HttpHeader_t * httpHeader);

#endif // HTTP_HANDLER_H

//#pragma once