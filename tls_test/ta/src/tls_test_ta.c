#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>


#include <tls_test_ta.h>
//#include "../../socket_test/ta/include/socket_test_ta.h"

//#include "certs/_.herokuapp.com.pem.h"
#include "certs/_.lisha.ufsc.br.pem.h"
#include "socket_handler.h"
#include "tls_handler.h"


#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/ssl.h>
#include <mbedtls/x509.h>
#include <mbedtls/debug.h>
#include <mbedtls/certs.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

struct tls_handle_t {
	TEE_TASessionHandle sess;

	mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config conf;
    mbedtls_x509_crt * cacert;
};

//TEE_UUID uuid_socket = TA_SOCKET_TEST_UUID;

TEE_Result TA_CreateEntryPoint(void)
{
	DMSG(" tls_test");

	return TEE_SUCCESS;
}

void TA_DestroyEntryPoint(void)
{
	DMSG(" tls_test");
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

	struct tls_handle_t *tls_handle;
	
	tls_handle = TEE_Malloc(sizeof(struct tls_handle_t), 0);
	if (!tls_handle)
		return TEE_ERROR_OUT_OF_MEMORY;

	tls_handle->cacert = TEE_Malloc(sizeof(mbedtls_x509_crt), 0);

	*sess_ctx = (void *)tls_handle;

	DMSG("tls_test");
	return TEE_SUCCESS;
}

void TA_CloseSessionEntryPoint(void *sess_ctx)
{
	struct tls_handle_t *tls_handle = (struct tls_handle_t *)sess_ctx;
	TEE_Free(tls_handle->cacert);
	TEE_Free(tls_handle);

	DMSG(" tls_test");
}

static TEE_Result ta_tls_close(void *sess_ctx, uint32_t param_types,
	TEE_Param params[4])
{
	struct tls_handle_t *tls_handle = (struct tls_handle_t *)sess_ctx;
	TEE_Result err;

	DMSG("TA_TLS_CLOSE");

    mbedtls_ssl_close_notify( &tls_handle->ssl );

	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE);
	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	err = socket_handler_close(&tls_handle->sess, exp_param_types, params);

	if ( err != TEE_SUCCESS)
		return err;

	finish_tls_structures(&tls_handle->ssl, &tls_handle->conf, \
		&tls_handle->entropy, &tls_handle->ctr_drbg, tls_handle->cacert);

	return TEE_SUCCESS;
}


static TEE_Result ta_tls_open(void *sess_ctx, uint32_t param_types,
	TEE_Param params[4])
{
	struct tls_handle_t *tls_handle = (struct tls_handle_t *)sess_ctx;
	TEE_Result err;
	
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
						   TEE_PARAM_TYPE_MEMREF_INPUT,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE);

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	err = socket_handler_open(&tls_handle->sess, exp_param_types, params);
	if( err != TEE_SUCCESS) {
		EMSG("Socket open failed");
		return err;
	}
	
	initialize_tls_structures(&tls_handle->ssl, &tls_handle->conf, \
			&tls_handle->entropy, &tls_handle->ctr_drbg, tls_handle->cacert);


	if(initialize_ctr_drbg(&tls_handle->entropy, &tls_handle->ctr_drbg, "tls_test") != 0) {
	    EMSG( "\n  ! initialize_ctr_drbg failed" );
		goto exit;
    }
	// /*
	if(set_ca_root_certificate(tls_handle->cacert, \
				(const unsigned char *) lisha_ca_crt, lisha_ca_crt_len ) != 0) {
	    EMSG( "\n  ! initialize_certificates failed" );
		goto exit;
    }
	// */

    if(setting_up_tls(&tls_handle->conf, &tls_handle->ctr_drbg, tls_handle->cacert) != 0) {
	    EMSG( "\n  ! setting_up_tls failed" );
		goto exit;
    }

    if(assign_configuration(&tls_handle->ssl, &tls_handle->conf) != 0) {
	    EMSG( "\n  ! assign_configuration failed" );
		goto exit;
    }

	if(set_hostname( &tls_handle->ssl, (const char *) params[1].memref.buffer ) != 0) {
	    EMSG( "\n  ! set_hostname failed" );
		goto exit;
    }

	set_bio(&tls_handle->ssl, &tls_handle->sess, f_send, f_recv, NULL);

    if(handshake(&tls_handle->ssl) != 0) {
	    EMSG( "\n  ! handshake failed" );
		goto exit;
    }

    if(verify_server_certificate(&tls_handle->ssl) != 0) {
	    EMSG( "\n  ! verify_server_certificate failed" );
		//goto exit;
    }
	return TEE_SUCCESS;

exit:
	EMSG( "  exit\n  ! connection closed due to an error");
	
	TEE_Param op[4];
	memset(op, 0x0, sizeof(op));
	
	exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_NONE);
	
	ta_tls_close(sess_ctx, exp_param_types, op);

	return TEE_ERROR_CANCEL;
}

static TEE_Result ta_tls_send(void *sess_ctx, uint32_t param_types,
	TEE_Param params[4])
{
	struct tls_handle_t *tls_handle = (struct tls_handle_t *)sess_ctx;
	int ret;
	
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
						   TEE_PARAM_TYPE_VALUE_OUTPUT,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE);

	DMSG("has been called");

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	int len = params[0].memref.size;

    while( ( ret = mbedtls_ssl_write( &tls_handle->ssl,(const unsigned char *) params[0].memref.buffer, len ) ) <= 0 )
    {
        if( ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE )
        {
            EMSG( " failed\n  ! mbedtls_ssl_write returned %d\n\n", ret );
            return TEE_ERROR_CANCEL;
        }
    }
	params[1].value.a = ret;
	return TEE_SUCCESS;
}

static TEE_Result ta_tls_recv(void *sess_ctx, uint32_t param_types,
	TEE_Param params[4])
{
	struct tls_handle_t *tls_handle = (struct tls_handle_t *)sess_ctx;
	int ret;


	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_OUTPUT,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE);

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;
	int len = params[0].memref.size -1;
    do
    {
        memset( params[0].memref.buffer, 0, params[0].memref.size );
        ret = mbedtls_ssl_read( &tls_handle->ssl, (unsigned char *) params[0].memref.buffer, len );

        if( ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE )
            continue;

        if( ret == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY ) {
			EMSG("Error ssl read: %d\n ret == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY", ret);
			params[0].memref.size = ret;
			break;
		}
		if( ret < 0) {
			EMSG("Error ssl read: %d -0x%x\n ret < 0", ret, -ret);
			params[0].memref.size = ret;
			break;
		}

		params[0].memref.size = ret;
		break;
    }
    while( 1 );

	return TEE_SUCCESS;
}


TEE_Result TA_InvokeCommandEntryPoint(void *sess_ctx,
			uint32_t cmd_id,
			uint32_t param_types, TEE_Param params[4])
{
	switch (cmd_id) {
	case TA_TLS_OPEN_CMD:
		return ta_tls_open(sess_ctx, param_types, params);
	case TA_TLS_CLOSE_CMD:
		return ta_tls_close(sess_ctx, param_types, params);
	case TA_TLS_SEND_CMD:
		return ta_tls_send(sess_ctx, param_types, params);
	case TA_TLS_RECV_CMD:
		return ta_tls_recv(sess_ctx, param_types, params);
	default:
		return TEE_ERROR_NOT_SUPPORTED;
	}
}