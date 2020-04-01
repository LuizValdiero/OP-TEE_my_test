#include <inttypes.h>
#include <tee_internal_api.h>
#include <aes_serial_ta.h>

struct cipher_handle_t {
	TEE_OperationHandle op;
	TEE_ObjectHandle key;
};
/*
typedef struct aes_ctr_key_t {
  char key[16];
  char iv[16];
}

static aes_ctr_key_t const aes_ctr_key {
  .key = {0x99, 0xF3, 0xCC, 0xA3, 0xFC, 0xC7, 0x10, 0x76, 0xAC, 0x16,
          0x86, 0x41, 0xD9, 0x06, 0xCE, 0xB5},
  .iv = {0x65, 0x04, 0xEF, 0x3F, 0x0D, 0xBF, 0xBE, 0x2A, 0xDD, 0x1D,
          0x1D, 0x39, 0x60, 0xC3, 0x39, 0x73}
};
*/


TEE_Result prepare_cipher(uint32_t mode_code, struct cipher_handle_t * handle) {
	uint32_t algo = TEE_ALG_AES_CTR;
	// mode
	//TEE_MODE_ENCRYPT
	//TEE_MODE_ENCRYPT
	uint32_t mode = (mode_code) ? TEE_MODE_ENCRYPT : TEE_MODE_DECRYPT;  
	uint32_t key_size = 16; //128 bits
	uint32_t iv_size = 16;
	
	TEE_Attribute attr;
	TEE_Result res;
	//char *key = &aes_ctr_key->key;
	char key[16] = {0x99, 0xF3, 0xCC, 0xA3, 0xFC, 0xC7, 0x10, 0x76, 0xAC, 0x16,
          0x86, 0x41, 0xD9, 0x06, 0xCE, 0xB5};
	//char *iv = &aes_ctr_key->iv;
	char iv[16] = {0x65, 0x04, 0xEF, 0x3F, 0x0D, 0xBF, 0xBE, 0x2A, 0xDD, 0x1D,
          0x1D, 0x39, 0x60, 0xC3, 0x39, 0x73};

	/* Free potential previous operation */
	if (handle->op != TEE_HANDLE_NULL)
		TEE_FreeOperation(handle->op);

	/* Allocate operation: AES/CTR, mode and size from params */
	res = TEE_AllocateOperation(&handle->op,
		algo,
		mode,
		key_size * 8);
	
	if (res != TEE_SUCCESS) {
		EMSG("Failed to allocate operation");
		handle->op = TEE_HANDLE_NULL;
		return res;
	}

	/* Free potential previous transient object */
	if (handle->key != TEE_HANDLE_NULL)
		TEE_FreeTransientObject(handle->key);

	/* Allocate transient object according to target key size */
	res = TEE_AllocateTransientObject(TEE_TYPE_AES,
		key_size * 8,
		&handle->key);
	
	if (res != TEE_SUCCESS) {
		EMSG("Failed to allocate transient object");
		handle->key = TEE_HANDLE_NULL;
		return res;
	}

	// Free ???
	//key = TEE_Malloc(key_size, 0);
	//if (!key) {
	//	return TEE_ERROR_OUT_OF_MEMORY;
	//}
	//memcpy(key, aes_ctr_key->key, key_size);

	TEE_InitRefAttribute(&attr, TEE_ATTR_SECRET_VALUE, key, key_size);

	res = TEE_PopulateTransientObject(handle->key, &attr, 1);
	if (res != TEE_SUCCESS) {
		EMSG("TEE_PopulateTransientObject failed, %x", res);
		return res;
	}

	res = TEE_SetOperationKey(handle->op, handle->key);
	if (res != TEE_SUCCESS) {
		EMSG("TEE_SetOperationKey failed %x", res);
		return res;
	}
	
	TEE_CipherInit(handle->op, iv, iv_size);
	return TEE_SUCCESS;
}


TEE_Result cmd_encrypt(void *session, uint32_t mode_code, uint32_t param_types, TEE_Param params[4]) {
	
	struct cipher_handle_t *cipher_handle = (struct cipher_handle_t *)session;
	TEE_Result res;
	
	// test param types
	const uint32_t exp_param_types =
		TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
				TEE_PARAM_TYPE_MEMREF_OUTPUT,
				TEE_PARAM_TYPE_NONE,
				TEE_PARAM_TYPE_NONE);	
	
	/* Safely get the invocation parameters */
	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	if (params[1].memref.size != params[0].memref.size) {
		EMSG("Bad sizes: in %d, out %d", params[0].memref.size,
						 params[1].memref.size);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	// 1 - encrypt
	// 0 - decrypt
	res = prepare_cipher( mode_code, cipher_handle);
	if (res != TEE_SUCCESS) {
		EMSG("Error: prepare_cipher");
		return res;
	}

	return TEE_CipherUpdate(cipher_handle->op,
				params[0].memref.buffer, params[0].memref.size,
				params[1].memref.buffer, &params[1].memref.size);
}


TEE_Result TA_CreateEntryPoint(void)
{
	/* Nothing to do */
	return TEE_SUCCESS;
}

void TA_DestroyEntryPoint(void)
{
	/* Nothing to do */
}

TEE_Result TA_OpenSessionEntryPoint(uint32_t __unused param_types,
					TEE_Param __unused params[4],
					void **session)
{
	struct cipher_handle_t *cipher_handle;
	
	/*
	 * Allocate and init state for the session.
	 */
	cipher_handle = TEE_Malloc(sizeof(struct cipher_handle_t *), 0);
	if (!cipher_handle)
		return TEE_ERROR_OUT_OF_MEMORY;

	cipher_handle->op = TEE_HANDLE_NULL;
	cipher_handle->key = TEE_HANDLE_NULL;
	
	*session = (void *)cipher_handle;
	return TEE_SUCCESS;
}

void TA_CloseSessionEntryPoint(void *session)
{
	struct cipher_handle_t *cipher_handle = (struct cipher_handle_t *)session;

	/* Release the session resources */
	if (cipher_handle->key != TEE_HANDLE_NULL)
		TEE_FreeTransientObject(cipher_handle->key);
	if (cipher_handle->op != TEE_HANDLE_NULL)
		TEE_FreeOperation(cipher_handle->op);

	TEE_Free(cipher_handle);
}

TEE_Result TA_InvokeCommandEntryPoint(void *session, uint32_t cmd,
				      uint32_t param_types,
				      TEE_Param params[4])
{
	switch (cmd) {
	case TA_DECRYPT:
		return cmd_encrypt(session, TA_DECRYPT, param_types, params);
	case TA_ENCRYPT:
		return cmd_encrypt(session, TA_ENCRYPT, param_types, params);
	default:
		EMSG("Command ID %#" PRIx32 " is not supported", cmd);
		return TEE_ERROR_NOT_SUPPORTED;
	}
}
