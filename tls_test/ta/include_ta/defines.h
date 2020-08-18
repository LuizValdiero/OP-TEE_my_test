#ifndef DEFINES_H
#define DEFINES_H

//#define REE
#define DEBUG

#ifndef REE
#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>

#else
#include <stdio.h>

#endif

#include <stdint.h>

typedef struct buffer_t {
    uint32_t buffer_size;
    unsigned char * buffer;
} buffer_t;

#ifdef REE
    #define DMSG printf
    #define IMSG printf
    #define EMSG printf

    #define TEE_Malloc(size, val) Malloc(size)
    #define TEE_Free free

#endif

#ifndef DEBUG
    #undef DMSG
    #undef IMSG
    #undef EMSG
    #define DMSG // 
    #define IMSG // 
    #define EMSG // 

#endif

#ifndef REE
    #define CODE_SUCCESS TEE_SUCCESS
    #define CODE_ERROR_GENERIC TEE_ERROR_GENERIC
    #define CODE_ERROR_CANCEL TEE_ERROR_CANCEL
    #define CODE_ERROR_NOT_IMPLEMENTED TEE_ERROR_NOT_IMPLEMENTED
    #define CODE_ERROR_NOT_SUPPORTED TEE_ERROR_NOT_SUPPORTED
    #define CODE_ERROR_OUT_OF_MEMORY TEE_ERROR_OUT_OF_MEMORY
    #define CODE_ERROR_COMMUNICATION TEE_ERROR_COMMUNICATION
    #define CODE_ERROR_SECURITY TEE_ERROR_SECURITY
    #define CODE_ERROR_SHORT_BUFFER TEE_ERROR_SHORT_BUFFER

#else
    #define CODE_SUCCESS 0
    #define CODE_ERROR_GENERIC -1
    #define CODE_ERROR_CANCEL -2
    #define CODE_ERROR_NOT_IMPLEMENTED -3
    #define CODE_ERROR_NOT_SUPPORTED -4
    #define CODE_ERROR_OUT_OF_MEMORY -5
    #define CODE_ERROR_COMMUNICATION -6
    #define CODE_ERROR_SECURITY -7
    #define CODE_ERROR_SHORT_BUFFER -8

#endif

#endif // DEFINES_H