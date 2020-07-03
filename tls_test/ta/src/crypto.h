#ifndef _CRYPTO_H
#define _CRYPTO_H

#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>

#include <stdlib.h>
#include <unistd.h>
#include <string.h>

struct cipher_handle_t {
	TEE_OperationHandle op;
	TEE_ObjectHandle key;
};

struct buffer_t {
    uint32_t buffer_size;
    unsigned char * buffer;
};

struct  __attribute__((__packed__)) crypto_header_t {
    uint32_t encrypted_size;
    unsigned char iv[16];
};


TEE_Result gerate_iv(struct buffer_t * iv);

TEE_Result initialize_crypto(struct cipher_handle_t * cipher, uint32_t algorithm, \
        uint32_t mode, char  * key, uint32_t key_size);

void finish_crypto(struct cipher_handle_t * cipher);

TEE_Result initialize_cipher(struct cipher_handle_t * cipher, uint32_t algorithm, \
        uint32_t mode, char  * key, uint32_t key_size);

TEE_Result decrypt_data(struct cipher_handle_t * cipher, \
                struct buffer_t * iv, \
                struct buffer_t * cipher_buffer, \
                struct buffer_t * plain_buffer);

TEE_Result create_encrypted_data(struct cipher_handle_t * cipher, \
                struct buffer_t * iv, \
                struct buffer_t * plain_buffer, \
                struct buffer_t * cipher_buffer);

/*
void print_buffer(struct buffer_t * buffer);
void print_buffer(struct buffer_t * buffer) {
    for (uint32_t i = 0; i< buffer->buffer_size; i++)
        DMSG("(%d) %x", i, buffer->buffer[i]);
}
*/
#endif // _CRYPTO_H