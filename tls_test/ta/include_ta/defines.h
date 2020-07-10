
#ifndef DEFINES_H
#define DEFINES_H

#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>

#include <stdint.h>

typedef struct buffer_t {
    uint32_t buffer_size;
    unsigned char * buffer;
} buffer_t;

/*

https://iot.lisha.ufsc.br:3000/d/A3NN9W2iz/tutorial?editPanel=2&orgId=1&from=1594241154624&to=1594241191435

domain: tutorial
username: tutorial
password: tuto20182

{ "smartdata" :[{
"version" : "1.1",
"unit" : 2224179556,
"value" : 10,
"error" : 0,
"confidence" : 0,
"x" : 0,
"y" : 1,
"z" : 2,
"t" : 1594241175706000,
"dev" : 0
}],
"credentials": {
"domain": "tutorial",
"username": "tutorial",
"password": "tuto20182"
}}

*/
#endif // DEFINES_H