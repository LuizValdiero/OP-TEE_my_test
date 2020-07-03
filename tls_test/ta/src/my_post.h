#ifndef _MY_POST_H
#define _MY_POST_H

#include <string.h>

#include "data_handler.h"
#include "http_handler.h"

int mount_body(char * buffer, int size, int (*print)(char *, int, void*), void * data, struct Credentials * credential);

int mount_request(char * buff, int size, struct HttpHeader_t * httpHeader, data_type_t data_type, void * data, struct Credentials * credentials);

/*
2.1. Query data URL: https://iot.lisha.ufsc.br/api/get.php
Body: 2.1 series
2.2. Create series URL for create: https://iot.lisha.ufsc.br/api/create.php
Body: 2.2 series
2.3. Insert data URL: https://iot.lisha.ufsc.br/api/put.php
Body: 2.3 smartdata

versio 1.1
3.1. Create series (Binary) URL for create: https://iot.lisha.ufsc.br/api/create.php
Body: Series
3.2. Insert data (Binary) URL: https://iot.lisha.ufsc.br/api/put.php
Body: SmartData
*/

#endif // _MY_POST_H

