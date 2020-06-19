#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>


#include <x509_test_ta.h>

//#include <mbedtls/error.h>

#include <mbedtls/ssl.h>
#include <mbedtls/x509.h>
#include <mbedtls/debug.h>
#include <mbedtls/certs.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

struct cacert_test_handle_t {
	mbedtls_x509_crt * cacert;
};

TEE_Result TA_CreateEntryPoint(void)
{
	DMSG(" x509_test");

	return TEE_SUCCESS;
}

void TA_DestroyEntryPoint(void)
{
	DMSG(" x509_test");
}

TEE_Result TA_OpenSessionEntryPoint(uint32_t param_types,
		TEE_Param __maybe_unused params[4],
		void **sess_ctx)
{
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE);
	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	/* Unused parameters */
	(void)&params;

	struct cacert_test_handle_t *cacert_test_handle;
	
	cacert_test_handle = TEE_Malloc(sizeof(struct cacert_test_handle_t), 0);
	if (!cacert_test_handle)
		return TEE_ERROR_OUT_OF_MEMORY;

	cacert_test_handle->cacert = TEE_Malloc( sizeof(mbedtls_x509_crt), TEE_MALLOC_FILL_ZERO);

	*sess_ctx = (void *)cacert_test_handle;


	DMSG(" x509_test");
	return TEE_SUCCESS;
}

void TA_CloseSessionEntryPoint(void *sess_ctx)
{
	(void)&sess_ctx;

	struct cacert_test_handle_t *cacert_test_handle = (struct cacert_test_handle_t *)sess_ctx;
	TEE_Free(cacert_test_handle->cacert);
	TEE_Free(cacert_test_handle);

	DMSG(" x509_test");
}

static TEE_Result x509_crt(void *sess_ctx, uint32_t param_types,
	TEE_Param params[4])
{
	(void)&sess_ctx;
	(void)&params;
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE);

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

    //mbedtls_x509_crt cacert = {};
	struct cacert_test_handle_t *cacert_test_handle = (struct cacert_test_handle_t *)sess_ctx;
	

    int ret;

    mbedtls_x509_crt_init( cacert_test_handle->cacert );


	DMSG(" len certificate %d", cacert_test_handle->cacert->raw.len);

    ret = mbedtls_x509_crt_parse( cacert_test_handle->cacert, (const unsigned char *) mbedtls_test_cas_pem, \
                          mbedtls_test_cas_pem_len );
    if( ret < 0 )
    {
        DMSG( " failed\n  !  mbedtls_x509_crt_parse returned -0x%x\n\n", -ret );
		//char error_buf[100];
		//mbedtls_strerror( ret, error_buf, 100 );
		//DMSG("\n  ! Last error was:-0x%x - %s\n\n", -ret, error_buf );
    } else {
        DMSG( " \n  .  mbedtls_x509_crt_parse returned 0x%x\n\n", ret );
	}

	DMSG(" len certificate %d", cacert_test_handle->cacert->raw.len);

	mbedtls_x509_crt_free(cacert_test_handle->cacert);

	return TEE_SUCCESS;
}

static TEE_Result x509_crt2(void *sess_ctx, uint32_t param_types,
	TEE_Param params[4])
{
	(void)&sess_ctx;
	(void)&params;
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_OUTPUT,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE);

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

    //mbedtls_x509_crt cacert = {};

    int ret;

    //mbedtls_x509_crt_init( &cacert );
	mbedtls_x509_crt_init( (mbedtls_x509_crt *) params[0].memref.buffer);

    ret = mbedtls_x509_crt_parse( (mbedtls_x509_crt *) params[0].memref.buffer, (const unsigned char *) mbedtls_test_cas_pem, \
                          mbedtls_test_cas_pem_len );
    if( ret < 0 )
    {
        DMSG( " failed\n  !  mbedtls_x509_crt_parse returned -0x%x\n\n", -ret );
		//char error_buf[100];
		//mbedtls_strerror( ret, error_buf, 100 );
		//DMSG("\n  ! Last error was:-0x%x - %s\n\n", -ret, error_buf );
    } else {
        DMSG( " \n  .  mbedtls_x509_crt_parse returned 0x%x\n\n", ret );
	}

	//mbedtls_x509_crt_free(&cacert);

	return TEE_SUCCESS;
}

TEE_Result TA_InvokeCommandEntryPoint(void *sess_ctx,
			uint32_t cmd_id,
			uint32_t param_types, TEE_Param params[4])
{
	switch (cmd_id) {
	case TA_X509_CMD:
		return x509_crt(sess_ctx, param_types, params);
	case TA_X509_CMD2:
		return x509_crt2(sess_ctx, param_types, params);
	default:
		return TEE_ERROR_NOT_SUPPORTED;
	}
}