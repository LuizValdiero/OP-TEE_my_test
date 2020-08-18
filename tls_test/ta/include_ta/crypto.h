#ifndef _CRYPTO_H
#define _CRYPTO_H

#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>

#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include "defines.h"

struct cipher_handle_t {
	TEE_OperationHandle op;
	TEE_ObjectHandle key;
};

TEE_Result gerate_iv(buffer_t * iv);

TEE_Result initialize_crypto(struct cipher_handle_t * cipher, uint32_t algorithm, \
        uint32_t mode, char  * key, uint32_t key_size);

void finish_crypto(struct cipher_handle_t * cipher);

TEE_Result initialize_cipher(struct cipher_handle_t * cipher, uint32_t algorithm, \
        uint32_t mode, char  * key, uint32_t key_size);

TEE_Result decrypt_data(struct cipher_handle_t * cipher, \
                buffer_t * iv, \
                buffer_t * cipher_buffer, \
                buffer_t * plain_buffer);

TEE_Result encrypt_data(struct cipher_handle_t * cipher, \
                buffer_t * iv, \
                buffer_t * plain_buffer, \
                buffer_t * cipher_buffer);

/*
void print_buffer(buffer_t * buffer);
void print_buffer(buffer_t * buffer) {
    for (uint32_t i = 0; i< buffer->buffer_size; i++)
        DMSG("(%d) %x", i, buffer->buffer[i]);
}
*/
#endif // _CRYPTO_H