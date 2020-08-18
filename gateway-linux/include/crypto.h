#ifndef _CRYPTO_H
#define _CRYPTO_H
/*
#include "mbedtls/aes.h" // aes it self
#include "mbedtls/ctr_drbg.h" // pseudorandom generator based on aes
#include "mbedtls/entropy.h" // entropy function for ctr_drbg
#include "mbedtls/error.h"
// */
//*
#include <mbedtls/aes.h> // aes it self
#include <mbedtls/ctr_drbg.h> // pseudorandom generator based on aes
#include <mbedtls/entropy.h> // entropy function for ctr_drbg
#include <mbedtls/error.h>
// */
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <inttypes.h>

#include "defines.h"

typedef struct cipher_handle_t {
    mbedtls_aes_context aes;
    size_t nc_off;
    mbedtls_ctr_drbg_context random_context;
    mbedtls_entropy_context entropy_context;
} cipher_handle_t;

int gerate_iv(cipher_handle_t * cipher, buffer_t * iv);

int initialize_crypto(cipher_handle_t * cipher, char  * key, uint32_t key_size);
void finish_crypto(cipher_handle_t * cipher);
int initialize_cipher(cipher_handle_t * cipher, \
                char  * key, uint32_t key_size);

int decrypt_data(mbedtls_aes_context * aes, size_t * nc_off, \
                buffer_t * iv, \
                buffer_t * cipher_buffer, \
                buffer_t * plain_buffer);

int encrypt_data(mbedtls_aes_context * aes, size_t * nc_off, \
                buffer_t * iv, \
                buffer_t * plain_buffer, \
                buffer_t * cipher_buffer);

#endif // _CRYPTO_H