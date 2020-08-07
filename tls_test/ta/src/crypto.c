#include <crypto.h>


TEE_Result gerate_iv(buffer_t * iv) {
	TEE_GenerateRandom(iv->buffer, iv->buffer_size);
	return TEE_SUCCESS;
}


TEE_Result initialize_crypto(struct cipher_handle_t * cipher, uint32_t algorithm, \
        uint32_t mode, char  * key, uint32_t key_size) {
	cipher->op = TEE_HANDLE_NULL;
	cipher->key = TEE_HANDLE_NULL;
	return initialize_cipher(cipher, algorithm, mode, key, key_size);
}

void finish_crypto(struct cipher_handle_t * cipher) {
	if (cipher->key != TEE_HANDLE_NULL)
		TEE_FreeTransientObject(cipher->key);
	if (cipher->op != TEE_HANDLE_NULL)
		TEE_FreeOperation(cipher->op);
}

TEE_Result initialize_cipher(struct cipher_handle_t * cipher, uint32_t algorithm, \
        uint32_t mode, char  * key, uint32_t key_size) {
    
	TEE_Attribute attr;
	TEE_Result res;
	
	if (cipher->op != TEE_HANDLE_NULL)
		TEE_FreeOperation(cipher->op);

	res = TEE_AllocateOperation(&cipher->op, algorithm, mode, key_size * 8);	
	if (res != TEE_SUCCESS) {
		EMSG("Failed to allocate operation");
		cipher->op = TEE_HANDLE_NULL;
		return res;
	}

	if (cipher->key != TEE_HANDLE_NULL)
		TEE_FreeTransientObject(cipher->key);

	res = TEE_AllocateTransientObject(TEE_TYPE_AES,
		key_size * 8,
		&cipher->key);	
	if (res != TEE_SUCCESS) {
		EMSG("Failed to allocate transient object");
		cipher->key = TEE_HANDLE_NULL;
		return res;
    }
	
    TEE_InitRefAttribute(&attr, TEE_ATTR_SECRET_VALUE, key, key_size);

	res = TEE_PopulateTransientObject(cipher->key, &attr, 1);
	if (res != TEE_SUCCESS) {
		EMSG("TEE_PopulateTransientObject failed, %x", res);
		return res;
	}

	res = TEE_SetOperationKey(cipher->op, cipher->key);
	if (res != TEE_SUCCESS) {
		EMSG("TEE_SetOperationKey failed %x", res);
		return res;
	}    
	return TEE_SUCCESS;
}


TEE_Result decrypt_data(struct cipher_handle_t * cipher, \
                buffer_t * iv, \
                buffer_t * cipher_buffer, \
                buffer_t * plain_buffer)
{
    plain_buffer->buffer = TEE_Malloc(cipher_buffer->buffer_size, 0);
    plain_buffer->buffer_size = cipher_buffer->buffer_size;

    TEE_CipherInit(cipher->op, iv->buffer, iv->buffer_size);
    
    if(TEE_SUCCESS != TEE_CipherUpdate(
        cipher->op, (void *)cipher_buffer->buffer, cipher_buffer->buffer_size, \
        (void *)plain_buffer->buffer, &plain_buffer->buffer_size))
    {
        DMSG("\n    ! ERROR TEE_CipherUpdate\n");
        return TEE_ERROR_CANCEL;
    }
    return TEE_SUCCESS;
}


TEE_Result create_encrypted_data(struct cipher_handle_t * cipher, \
                buffer_t * iv, \
                buffer_t * plain_buffer, \
                buffer_t * cipher_buffer)
{
    size_t encrypted_size = plain_buffer->buffer_size *2;
    unsigned char encrypted_data[encrypted_size];
    
	TEE_CipherInit(cipher->op, iv->buffer, iv->buffer_size);

    if(TEE_SUCCESS != TEE_CipherUpdate( cipher->op, \
                plain_buffer->buffer, plain_buffer->buffer_size, \
                encrypted_data, &encrypted_size))
    {
        DMSG("\n    ! ERROR TEE_CipherUpdate\n");
        return TEE_ERROR_CANCEL;
    }
    
    cipher_buffer->buffer = TEE_Malloc(encrypted_size, 0);
    memcpy(cipher_buffer->buffer, encrypted_data, encrypted_size);
    cipher_buffer->buffer_size = encrypted_size;
    return TEE_SUCCESS;
}
