#include "crypto.h"

int gerate_iv(cipher_handle_t * cipher, buffer_t * iv) {
    mbedtls_ctr_drbg_random(&cipher->random_context, iv->buffer, iv->buffer_size);
    return CODE_SUCCESS;
}

int initialize_crypto(cipher_handle_t * cipher, char  * key, uint32_t key_size) {
//int initialize_crypto(cipher_handle_t * cipher, char  * key, uint32_t key_size) {
    //if (&cipher->random_context == NULL)
        mbedtls_ctr_drbg_init(&cipher->random_context);
    //if (&cipher->entropy_context == NULL)
        mbedtls_entropy_init(&cipher->entropy_context);

    int res = mbedtls_ctr_drbg_seed(&cipher->random_context, mbedtls_entropy_func, \
                    &cipher->entropy_context, (unsigned char *)"", 0);

    if (res != 0) {
        mbedtls_entropy_free(&cipher->entropy_context);
        mbedtls_ctr_drbg_free(&cipher->random_context);
        EMSG("Failed to init radom generator");
        char error_buf[100];
        mbedtls_strerror( res, error_buf, 100 );
        EMSG("\n  ! Last error was:-0x%x - %s\n\n", -res, error_buf );  
    }
    return res || initialize_cipher(cipher, key, key_size);
}

void finish_crypto(cipher_handle_t * cipher) {
    if (&cipher->aes != NULL)
        mbedtls_aes_free(&cipher->aes);
    if (&cipher->random_context != NULL)
        mbedtls_ctr_drbg_free(&cipher->random_context);
    if (&cipher->entropy_context != NULL)
        mbedtls_entropy_free(&cipher->entropy_context);
}

int initialize_cipher(cipher_handle_t * cipher, \
                char  * key, uint32_t key_size)
{
    int res;

    if (&cipher->aes != NULL)
        mbedtls_aes_free(&cipher->aes);

    mbedtls_aes_init(&cipher->aes);

    res = mbedtls_aes_setkey_enc(&cipher->aes, (const unsigned char *) key, key_size * 8);
    
    //cipher->nonce_counter = [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0];
    cipher->nc_off = 0;

    if (res != 0) {
        EMSG("Failed to allocate operation");
        mbedtls_aes_free(&cipher->aes);
        return res;
    }
    return 0;
}


int decrypt_data(mbedtls_aes_context * aes, size_t * nc_off, \
                buffer_t * iv, \
                buffer_t * cipher_buffer, \
                buffer_t * plain_buffer)
{
    return create_encrypted_data(aes, nc_off, iv, cipher_buffer, plain_buffer);
}

int create_encrypted_data(mbedtls_aes_context * aes, size_t * nc_off, \
                buffer_t * iv, \
                buffer_t * plain_buffer, \
                buffer_t * cipher_buffer)
{
    cipher_buffer->buffer = malloc(plain_buffer->buffer_size);
    cipher_buffer->buffer_size = plain_buffer->buffer_size;
    
    int res;

    unsigned char stream_block[16] = {0};
    res = mbedtls_aes_crypt_ctr(aes, plain_buffer->buffer_size, nc_off, iv->buffer, stream_block, plain_buffer->buffer, cipher_buffer->buffer);
    
    if (res != 0) {
        DMSG("\n    ! ERROR mbedtls_aes_crypt_ctr for encrypt\n");
    }
    return res;
}