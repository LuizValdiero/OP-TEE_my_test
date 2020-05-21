#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>


#include <tls_test_ta.h>
#include "../../socket_test/ta/include/socket_test_ta.h"
#include "../../x509_test/ta/include/x509_test_ta.h"

#include <mbedtls/ecdsa.h>

#include <mbedtls/aes.h>
#include <mbedtls/base64.h>
#include <mbedtls/bignum.h>
#include <mbedtls/md5.h>
#include <mbedtls/rsa.h>
#include <mbedtls/sha256.h>

#include <mbedtls/error.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/ssl.h>
#include <mbedtls/x509.h>
#include <mbedtls/debug.h>
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

TEE_UUID uuid_socket = TA_SOCKET_TEST_UUID;
TEE_UUID uuid_x509_cert = TA_X509_TEST_UUID;

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

int f_send(void * sess_ctx, const unsigned char * buf, unsigned int len)
{
	struct tls_handle_t *tls_handle = (struct tls_handle_t *)sess_ctx;
	
	DMSG("has been called\n");

	TEE_Result err;
	uint32_t err_origin;

	TEE_Param op[4];
	memset(&op, 0, sizeof(op));
	op[0].memref.buffer = buf;
	op[0].memref.size = len;

	uint32_t ptypes = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
						   TEE_PARAM_TYPE_VALUE_OUTPUT,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE);
	
	DMSG("\n  . f_send prepare to invokeTACommand\n");
	err = TEE_InvokeTACommand( tls_handle->sess, TEE_TIMEOUT_INFINITE,
		TA_SOCKET_SEND_CMD,  
		ptypes,
		op, &err_origin);
	
	DMSG("\n  . f_send sent %d bytes, res: %x\n", op[1].value.a, err);
		
	if (err != TEE_SUCCESS)
		return err;

	return op[1].value.a;
}

int f_recv(void * sess_ctx, unsigned char * buf, unsigned int len)
{
	struct tls_handle_t *tls_handle = (struct tls_handle_t *)sess_ctx;
	
	TEE_Result err;
	uint32_t err_origin;

	DMSG("has been called");

	TEE_Param op[4];
	memset(&op, 0, sizeof(op));
	op[0].memref.buffer = buf;
	op[0].memref.size = len;

	uint32_t ptypes = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_OUTPUT,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE);
	
	err = TEE_InvokeTACommand( tls_handle->sess, TEE_TIMEOUT_INFINITE,
		TA_SOCKET_RECV_CMD,  
		ptypes,
		op, &err_origin);
	if (err != TEE_SUCCESS)
		return err;

	return op[0].memref.size;
}

static int f_rng(void *rng __unused, unsigned char *output, size_t output_len)
{
	TEE_GenerateRandom(output, output_len);
	return 0;
}

int initialize_ctr_drbg(mbedtls_entropy_context * entropy,
	mbedtls_ctr_drbg_context * ctr_drbg,
	const char * pers)
{
	int ret;

	DMSG( "\n  . Seeding the random number generator..." );
    

    mbedtls_ctr_drbg_init( ctr_drbg );
	mbedtls_entropy_init( entropy );

    if( ( ret = mbedtls_ctr_drbg_seed( ctr_drbg, f_rng, entropy,
                               (const unsigned char *) pers,
                               strlen(pers) ) ) != 0 )
    {
	    DMSG(" failed\n  ! mbedtls_ctr_drbg_seed returned %x\n", ret );
		char error_buf[100];
		mbedtls_strerror( ret, error_buf, 100 );
		DMSG("\n  ! Last error was:-0x%x - %s\n\n", -ret, error_buf );
    }

	return ret;
}
// /*
int initialize_certificates(void * sess_ctx)
{
	struct tls_handle_t *tls_handle = (struct tls_handle_t *)sess_ctx;
	TEE_TASessionHandle sess_x509_cert;
	TEE_Result err;
	uint32_t err_origin;
	
	err = TEE_OpenTASession(&uuid_x509_cert, TEE_TIMEOUT_INFINITE, 
		0, NULL, &sess_x509_cert, &err_origin);
	
	if (err != TEE_SUCCESS)
	{
		DMSG("\n  ! openTaSession failed");
		return err;
	}

	uint32_t param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_OUTPUT,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE);

	TEE_Param op[4];
	memset(op, 0x0, sizeof(op));

	op[0].memref.buffer = &tls_handle->cacert;
	op[0].memref.size = sizeof(tls_handle->cacert);

	err = TEE_InvokeTACommand(sess_x509_cert, TEE_TIMEOUT_INFINITE,
		TA_X509_CMD2,  
		param_types,
		op, &err_origin);
	if (err != TEE_SUCCESS)
	{
		DMSG("\n  ! InvokeTACommand failed");
		return err;
	}
	
	TEE_CloseTASession(sess_x509_cert);
	return 0;
}
// */
int setting_up_tls(void * sess_ctx)
{
	struct tls_handle_t *tls_handle = (struct tls_handle_t *)sess_ctx;
	int ret;

	DMSG( "\n  . Setting up the SSL/TLS structure..." );

    mbedtls_ssl_init( &tls_handle->ssl );
    mbedtls_ssl_config_init( &tls_handle->conf );

	DMSG( "\n  . mbedtls_ssl_config_defaults");	
    if( ( ret = mbedtls_ssl_config_defaults( &tls_handle->conf,
                    MBEDTLS_SSL_IS_CLIENT,
                    MBEDTLS_SSL_TRANSPORT_STREAM,
                    MBEDTLS_SSL_PRESET_DEFAULT ) ) != 0 )
    {
        DMSG( " failed\n  ! mbedtls_ssl_config_defaults returned %d\n\n", ret );
		char error_buf[100];
		mbedtls_strerror( ret, error_buf, 100 );
		DMSG("\n  ! Last error was:-0x%x - %s\n\n", -ret, error_buf );
    }

/* OPTIONAL is not optimal for security,
     * but makes interop easier in this simplified example */
    DMSG( "\n  . mbedtls_ssl_conf_authmode");
	mbedtls_ssl_conf_authmode( &tls_handle->conf, MBEDTLS_SSL_VERIFY_OPTIONAL );
    DMSG( "\n  . mbedtls_ssl_conf_rng");
	mbedtls_ssl_conf_rng( &tls_handle->conf, f_rng, &tls_handle->ctr_drbg );
    DMSG( "\n  . mbedtls_ssl_conf_chain");	
	mbedtls_ssl_conf_ca_chain( &tls_handle->conf, &tls_handle->cacert, NULL );

	DMSG( "\n  . mbedtls_ssl_setup");	
    if( ( ret = mbedtls_ssl_setup( &tls_handle->ssl, &tls_handle->conf ) ) != 0 )
    {
        DMSG( " failed\n  ! mbedtls_ssl_setup returned %d\n\n", ret );
		char error_buf[100];
		mbedtls_strerror( ret, error_buf, 100 );
		DMSG("\n  ! Last error was:-0x%x - %s\n\n", -ret, error_buf );
    }

	// possivel problema, talvez deva copiar o conteudo
	// hostname nao pode ser endereco ip
	// utilizada para verificar certificado
	DMSG( "\n  . mbedtls_ssl_set_hostname");	
    if( ( ret = mbedtls_ssl_set_hostname( &tls_handle->ssl, "10.0.0.2" ) ) != 0 )
    {
        DMSG( " failed\n  ! mbedtls_ssl_set_hostname returned %d\n\n", ret );
		char error_buf[100];
		mbedtls_strerror( ret, error_buf, 100 );
		DMSG("\n  ! Last error was:-0x%x - %s\n\n", -ret, error_buf );
    }

    DMSG( "\n  . mbedtls_ssl_set_bio");	
	mbedtls_ssl_set_bio( &tls_handle->ssl, tls_handle, f_send, f_recv, NULL );
 
	return ret;
}

int handshake(void * sess_ctx)
{
	struct tls_handle_t *tls_handle = (struct tls_handle_t *)sess_ctx;
	int ret;

	DMSG( "\n  . Performing the SSL/TLS handshake..." );
    
    while( ( ret = mbedtls_ssl_handshake( &tls_handle->ssl ) ) != 0 )
    {
        if( ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE )
        {
			char error_buf[100];
        	mbedtls_strerror( ret, error_buf, 100 );
            DMSG( " failed\n  ! mbedtls_ssl_handshake returned -0x%x\n\n", -ret );
			DMSG("\n  ! Last error was:-0x%x - %s\n\n", -ret, error_buf );
            return ret;
        } else {
			DMSG( " .");
		}
    }

	return 0;
}

int verify_server_certificate(void * sess_ctx)
{
	struct tls_handle_t *tls_handle = (struct tls_handle_t *)sess_ctx;
	uint32_t flags;
	
	DMSG( "  . Verifying peer X.509 certificate..." );
    if( ( flags = mbedtls_ssl_get_verify_result( &tls_handle->ssl ) ) != 0 )
    {
        char vrfy_buf[512];

        DMSG( " failed\n" );

        mbedtls_x509_crt_verify_info( vrfy_buf, sizeof( vrfy_buf ), "  ! ", flags );

        DMSG( "%s\n", vrfy_buf );
    }

	return TEE_SUCCESS;
}


static TEE_Result tls_open(void *sess_ctx, uint32_t param_types,
	TEE_Param params[4])
{
	struct tls_handle_t *tls_handle = (struct tls_handle_t *)sess_ctx;
	TEE_Result err;
	uint32_t err_origin;
	
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
						   TEE_PARAM_TYPE_MEMREF_INPUT,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE);

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	err = TEE_OpenTASession(&uuid_socket, TEE_TIMEOUT_INFINITE, 
		0, NULL, &tls_handle->sess, &err_origin);
	
	if (err != TEE_SUCCESS)
	{
		DMSG("socket_test openTaSession error");
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
	// /*	
    if(initialize_ctr_drbg(&tls_handle->entropy, &tls_handle->ctr_drbg, "tls_test") != 0) {
	    DMSG( "\n  ! initialize_ctr_drbg failed" );
		goto exit;
    }
	// */
	// /*
	if(initialize_certificates(sess_ctx) != 0) {
	    DMSG( "\n  ! initialize_certificates failed" );
		goto exit;
    }
	// */
	
    if(setting_up_tls(sess_ctx) != 0) {
	    DMSG( "\n  ! setting_up_tls failed" );
		goto exit;
    }

    if(handshake(sess_ctx) != 0) {
	    DMSG( "\n  ! handshake failed" );
		goto exit;
    }

    if(verify_server_certificate(sess_ctx) != 0) {
	    DMSG( "\n  ! verify_server_certificate failed" );
		//goto exit;
    }

	return TEE_SUCCESS;

exit:
	DMSG( "  exit\n  ! connection closed due to an error");
	
    //mbedtls_x509_crt_free( &tls_handle->cacert );
    mbedtls_ssl_free( &tls_handle->ssl );
    mbedtls_ssl_config_free( &tls_handle->conf );
    mbedtls_ctr_drbg_free( &tls_handle->ctr_drbg );
    mbedtls_entropy_free( &tls_handle->entropy );

	TEE_Param op[4];
	memset(op, 0x0, sizeof(op));
	
	exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_NONE);
	

	DMSG( "  exit\n  InvokeTACommand TA_SOCKET_CLOSE_CMD");

	err = TEE_InvokeTACommand(tls_handle->sess, TEE_TIMEOUT_INFINITE,
		TA_SOCKET_CLOSE_CMD,  
		exp_param_types,
		op, &err_origin);
	if (err != TEE_SUCCESS)
		return err;

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