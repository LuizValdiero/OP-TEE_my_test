#ifndef HTTP_HANDLER_H
#define HTTP_HANDLER_H

#include <stdio.h>
#include <string.h>

enum method_t { GET,POST, PUT};
enum path_t { API_GET, API_POST, API_ATTACH};
enum content_type_t { JSON, OCTET_STREAM};

extern const char * method_list[];
extern const char * path_list[];
extern const char * content_type_list[];


struct HttpHeader_t {
    enum method_t method;
    enum path_t path;
    enum content_type_t content_type;
    const char * hostname;
    int content_length;
};

int mount_http_header(char * buff, int size, struct HttpHeader_t * httpHeader);

#endif // HTTP_HANDLER_H

//#pragma once