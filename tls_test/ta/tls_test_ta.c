#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>


#include <tls_test_ta.h>
#include "../../socket_test/ta/include/socket_test_ta.h"

//#include "mbedtls/debug.h"
//#include <mbedtls/net_sockets.h>
#include <mbedtls/ssl.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/error.h>
#include <mbedtls/certs.h>

#if !defined(MBEDTLS_CONFIG_FILE)
#include <mbedtls/config.h>
#else
#include MBEDTLS_CONFIG_FILE
#endif

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
    mbedtls_x509_crt cacert;
};

TEE_UUID uuid = TA_SOCKET_TEST_UUID;

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
	
	tls_handle = TEE_Malloc(sizeof(struct tls_handle_t *), 0);
	if (!tls_handle)
		return TEE_ERROR_OUT_OF_MEMORY;

	*sess_ctx = (void *)tls_handle;

	DMSG(" tls_test");
	return TEE_SUCCESS;
}

void TA_CloseSessionEntryPoint(void *sess_ctx)
{
	struct tls_handle_t *tls_handle = (struct tls_handle_t *)sess_ctx;
	TEE_Free(tls_handle);

	DMSG(" tls_test");
}


int socket_send(void * ctx, const unsigned char * buf, size_t len)
{
	
	TEE_Result err;
	uint32_t err_origin;

	TEE_Param op[4];
	memset(&op, 0, sizeof(op));
	op[0].memref.buffer = buf;
	op[0].memref.size = len;

	uint32_t ptypes = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
					  TEE_PARAM_TYPE_VALUE_OUTPUT, TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE);
	
	err = TEE_InvokeTACommand( ((struct tls_handle_t *) ctx)->sess, TEE_TIMEOUT_INFINITE,
		TA_SOCKET_SEND_CMD,  
		ptypes,
		op, &err_origin);
	if (err != TEE_SUCCESS)
		return err;

	return op[1].value.a;
}

int socket_recv(void *ctx, unsigned char *buf, size_t len)
{
	TEE_Result err;
	uint32_t err_origin;

	TEE_Param op[4];
	memset(&op, 0, sizeof(op));
	op[0].memref.buffer = buf;
	op[0].memref.size = len;

	uint32_t ptypes = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_OUTPUT,
					  TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE);
	
	err = TEE_InvokeTACommand( ((struct tls_handle_t *) ctx)->sess, TEE_TIMEOUT_INFINITE,
		TA_SOCKET_RECV_CMD,  
		ptypes,
		op, &err_origin);
	if (err != TEE_SUCCESS)
		return err;

	return op[0].memref.size;
}

static TEE_Result tls_open(void *sess_ctx, uint32_t param_types,
	TEE_Param params[4])
{
	struct tls_handle_t *tls_handle = (struct tls_handle_t *)sess_ctx;
	TEE_Result err;
	uint32_t err_origin;
	const char *pers = "ssl_client1";
    uint32_t flags;
	int ret;

	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
						   TEE_PARAM_TYPE_MEMREF_INPUT,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE);

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	err = TEE_OpenTASession(&uuid, TEE_TIMEOUT_INFINITE, 
		0, NULL, &tls_handle->sess, &err_origin);
	
	if (err != TEE_SUCCESS)
	{
		DMSG("tls_test: socket_test openTaSession error");
		return err;
	}

	err = TEE_InvokeTACommand(tls_handle->sess, TEE_TIMEOUT_INFINITE,
		TA_SOCKET_OPEN_CMD,  
		exp_param_types,
		params, &err_origin);
	if (err != TEE_SUCCESS)
	{
		DMSG("Socket open failed");
		return err;
	}
		

	/*
     * 0. Initialize the RNG and the session data
     */
    //mbedtls_net_init( &server_fd );
    mbedtls_ssl_init( &tls_handle->ssl );
    mbedtls_ssl_config_init( &tls_handle->conf );
    mbedtls_x509_crt_init( &tls_handle->cacert );
    mbedtls_ctr_drbg_init( &tls_handle->ctr_drbg );

    DMSG( "\n  . Seeding the random number generator..." );
    
    mbedtls_entropy_init( &tls_handle->entropy );
    if( ( ret = mbedtls_ctr_drbg_seed( &tls_handle->ctr_drbg, mbedtls_entropy_func, &tls_handle->entropy,
                               (const unsigned char *) pers,
                               strlen(pers) ) ) != 0 )
    {
    //    printf( " failed\n  ! mbedtls_ctr_drbg_seed returned %d\n", ret );
	    DMSG(" failed\n  ! mbedtls_ctr_drbg_seed returned %x\n", ret );
		switch (ret)
		{
			case -0x0034:
				DMSG("  ! MBEDTLS_ERR_CTR_DRBG_ENTROPY_SOURCE_FAILED\n");
				break;
			case -0x0036:
				DMSG("  ! MBEDTLS_ERR_CTR_DRBG_REQUEST_TOO_BIG\n");
				break;
			case -0x0038:
				DMSG("  ! MBEDTLS_ERR_CTR_DRBG_INPUT_TOO_BIG\n");
				break;
			case -0x003A:
				DMSG("  ! MBEDTLS_ERR_CTR_DRBG_FILE_IO_ERROR\n");
				break;
			default:
				DMSG("  ! MBEDTLS_ERR_CTR_DRBG_ENTROPY_SOURCE undefined\n");
				break;
		}
		goto exit;
    }

    /*
     * 0. Initialize certificates
     */
    DMSG( "  . Loading the CA root certificate ..." );
    //fflush( stdout );

    ret = mbedtls_x509_crt_parse( &tls_handle->cacert, (const unsigned char *) mbedtls_test_cas_pem,
                          mbedtls_test_cas_pem_len );
    if( ret < 0 )
    {
        DMSG( " failed\n  !  mbedtls_x509_crt_parse returned -0x%x\n\n", -ret );
		goto exit;
    }

    DMSG( "  . Setting up the SSL/TLS structure..." );
    //fflush( stdout );

    if( ( ret = mbedtls_ssl_config_defaults( &tls_handle->conf,
                    MBEDTLS_SSL_IS_CLIENT,
                    MBEDTLS_SSL_TRANSPORT_STREAM,
                    MBEDTLS_SSL_PRESET_DEFAULT ) ) != 0 )
    {
        DMSG( " failed\n  ! mbedtls_ssl_config_defaults returned %d\n\n", ret );
		goto exit;
    }

    //printf( " ok\n" );

/* OPTIONAL is not optimal for security,
     * but makes interop easier in this simplified example */
    mbedtls_ssl_conf_authmode( &tls_handle->conf, MBEDTLS_SSL_VERIFY_OPTIONAL );
    mbedtls_ssl_conf_ca_chain( &tls_handle->conf, &tls_handle->cacert, NULL );
    mbedtls_ssl_conf_rng( &tls_handle->conf, mbedtls_ctr_drbg_random, &tls_handle->ctr_drbg );
    //mbedtls_ssl_conf_dbg( &tls_handle->conf, my_debug, stdout );

    if( ( ret = mbedtls_ssl_setup( &tls_handle->ssl, &tls_handle->conf ) ) != 0 )
    {
        DMSG( " failed\n  ! mbedtls_ssl_setup returned %d\n\n", ret );
		goto exit;
    }

	// possivel problema, talvez deva copiar o conteudo
    if( ( ret = mbedtls_ssl_set_hostname( &tls_handle->ssl, params[1].memref.buffer ) ) != 0 )
    {
        DMSG( " failed\n  ! mbedtls_ssl_set_hostname returned %d\n\n", ret );
		goto exit;
    }

    mbedtls_ssl_set_bio( &tls_handle->ssl, &sess_ctx, socket_send, socket_recv, NULL );
 
    /*
     * 4. Handshake
     */
    DMSG( "  . Performing the SSL/TLS handshake..." );
    //fflush( stdout );

    while( ( ret = mbedtls_ssl_handshake( &tls_handle->ssl ) ) != 0 )
    {
        if( ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE )
        {
            DMSG( " failed\n  ! mbedtls_ssl_handshake returned -0x%x\n\n", -ret );
            goto exit;
        }
    }

    //printf( " ok\n" );

    /*
     * 5. Verify the server certificate
     */
    DMSG( "  . Verifying peer X.509 certificate..." );

    /* In real life, we probably want to bail out when ret != 0 */
    if( ( flags = mbedtls_ssl_get_verify_result( &tls_handle->ssl ) ) != 0 )
    {
        char vrfy_buf[512];

        DMSG( " failed\n" );

        mbedtls_x509_crt_verify_info( vrfy_buf, sizeof( vrfy_buf ), "  ! ", flags );

        DMSG( "%s\n", vrfy_buf );
    }
    //else
    DMSG( " TLS opened\n" );

	return TEE_SUCCESS;

exit:

    mbedtls_x509_crt_free( &tls_handle->cacert );
    mbedtls_ssl_free( &tls_handle->ssl );
    mbedtls_ssl_config_free( &tls_handle->conf );
    mbedtls_ctr_drbg_free( &tls_handle->ctr_drbg );
    mbedtls_entropy_free( &tls_handle->entropy );

	TEE_Param op[4];
	memset(op, 0x0, sizeof(op));
	err = TEE_InvokeTACommand(tls_handle->sess, TEE_TIMEOUT_INFINITE,
		TA_SOCKET_CLOSE_CMD,  
		exp_param_types,
		op, &err_origin);
	if (err != TEE_SUCCESS)
		return ret;

	TEE_CloseTASession(tls_handle->sess);

	return TEE_ERROR_CANCEL;
}

static TEE_Result tls_close(void *sess_ctx, uint32_t param_types,
	TEE_Param params[4])
{
	struct tls_handle_t *tls_handle = (struct tls_handle_t *)sess_ctx;
	TEE_Result err;
	uint32_t err_origin;

    mbedtls_ssl_close_notify( &tls_handle->ssl );

	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE);
	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;
	
	err = TEE_InvokeTACommand(tls_handle->sess, TEE_TIMEOUT_INFINITE,
		TA_SOCKET_CLOSE_CMD,  
		exp_param_types,
		params, &err_origin);
	if (err != TEE_SUCCESS)
		return err;

	mbedtls_x509_crt_free( &tls_handle->cacert );
    mbedtls_ssl_free( &tls_handle->ssl );
    mbedtls_ssl_config_free( &tls_handle->conf );
    mbedtls_ctr_drbg_free( &tls_handle->ctr_drbg );
    mbedtls_entropy_free( &tls_handle->entropy );

	TEE_CloseTASession(tls_handle->sess);
	return TEE_SUCCESS;
}

static TEE_Result tls_send(void *sess_ctx, uint32_t param_types,
	TEE_Param params[4])
{
	struct tls_handle_t *tls_handle = (struct tls_handle_t *)sess_ctx;
	//TEE_Result err;
	//uint32_t err_origin;
	int ret;
	
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
						   TEE_PARAM_TYPE_VALUE_OUTPUT,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE);

	DMSG("has been called");

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

//    len = sprintf( (char *) buffer_out, GET_REQUEST );
    while( ( ret = mbedtls_ssl_write( &tls_handle->ssl,(const unsigned char *) params[0].memref.buffer, params[0].memref.size ) ) <= 0 )
    {
        if( ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE )
        {
            //printf( " failed\n  ! mbedtls_ssl_write returned %d\n\n", ret );
            return TEE_ERROR_CANCEL;
        }
    }
	params[1].value.a = ret;
	return TEE_SUCCESS;
}

static TEE_Result tls_recv(void *sess_ctx, uint32_t param_types,
	TEE_Param params[4])
{
	struct tls_handle_t *tls_handle = (struct tls_handle_t *)sess_ctx;
	//TEE_Result err;
	//uint32_t err_origin;
	int ret;


	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_OUTPUT,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE);

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;
	
    do
    {
        //len = sizeof( buffer_in ) - 1;
        //memset( buffer_in, 0, sizeof( buffer_in ) );
        ret = mbedtls_ssl_read( &tls_handle->ssl, (unsigned char *) params[0].memref.buffer, params[0].memref.size );

        if( ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE )
            continue;

        if( ret == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY )
            params[0].memref.size = 0;
			break;
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
		return tls_open(sess_ctx, param_types, params);
	case TA_TLS_CLOSE_CMD:
		return tls_close(sess_ctx, param_types, params);
	case TA_TLS_SEND_CMD:
		return tls_send(sess_ctx, param_types, params);
	case TA_TLS_RECV_CMD:
		return tls_recv(sess_ctx, param_types, params);
	default:
		return TEE_ERROR_NOT_SUPPORTED;
	}
}