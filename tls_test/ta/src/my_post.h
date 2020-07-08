#ifndef _MY_POST_H
#define _MY_POST_H

#include <string.h>

#include "defines.h"
#include "data_handler.h"
#include "http_handler.h"

int mount_body(buffer_t * out, \
                int (*data_to_json)(buffer_t * out, int *displacement, buffer_t * data), \
                buffer_t * data, struct credentials_t * credential);

int mount_request(buffer_t * out, struct HttpHeader_t * httpHeader, \
                    int (*data_to_json)(buffer_t * out, int *displacement, buffer_t * data), \
                    buffer_t * data, struct credentials_t * credentials);
                    
#endif // _MY_POST_H

