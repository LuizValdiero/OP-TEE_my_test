#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>


#include <tls_test_ta.h>

#include "certs/_.lisha.ufsc.br.pem.h"

#include "socket_handler.h"
#include "tls_handler.h"
#include "my_post.h"
#include "crypto.h"

#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/ssl.h>
#include <mbedtls/x509.h>
#include <mbedtls/debug.h>
#include <mbedtls/certs.h>
#include <mbedtls/error.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

struct tls_handle_t {
	struct socket_handle_t socket_sess;

	struct HttpHeader_t * httpHeader;
	struct Credentials * credentials;

	struct cipher_handle_t cipher;	

	mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config conf;
    mbedtls_x509_crt * cacert;
};

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

	struct HttpHeader_t httpHeader = { \
        .method = POST, \
        .path = API_GET, \
        .content_type = JSON, \
        .hostname = "iot.lisha.ufsc.br", \
        .content_length = 0};

	uint32_t size = sizeof(httpHeader);
	tls_handle->httpHeader = TEE_Malloc( size, 0);
	if (!tls_handle->httpHeader)
		return TEE_ERROR_OUT_OF_MEMORY;

	memcpy(tls_handle->httpHeader, &httpHeader, size);
	
	struct Credentials credentials = { \
		.domain = "smartlisha", \
		.username = "", \
		.password = ""};

	size = sizeof(credentials);
	tls_handle->credentials = TEE_Malloc( size, 0);
	if (!tls_handle->credentials)
		return TEE_ERROR_OUT_OF_MEMORY;
	memcpy(tls_handle->credentials, &credentials, size);
	

	char key[16] = {0x99, 0xF3, 0xCC, 0xA3, 0xFC, 0xC7, 0x10, 0x76, 0xAC, 0x16,
          0x86, 0x41, 0xD9, 0x06, 0xCE, 0xB5};
	int key_size = 16;
	uint32_t algorithm = TEE_ALG_AES_CTR;

	initialize_crypto(&tls_handle->cipher, algorithm, TEE_MODE_ENCRYPT, key, key_size);

	tls_handle->cacert = TEE_Malloc(sizeof(mbedtls_x509_crt), 0);
	if (!tls_handle->cacert)
		return TEE_ERROR_OUT_OF_MEMORY;


	*sess_ctx = (void *)tls_handle;
	return TEE_SUCCESS;
}

void TA_CloseSessionEntryPoint(void *sess_ctx)
{
	struct tls_handle_t *tls_handle = (struct tls_handle_t *)sess_ctx;
	TEE_Free(tls_handle->cacert);

	finish_crypto(&tls_handle->cipher);

	TEE_Free(tls_handle->credentials);
	TEE_Free(tls_handle->httpHeader);

	TEE_Free(tls_handle);
}

static TEE_Result ta_tls_close(void *sess_ctx, uint32_t param_types,
	TEE_Param params[4])
{
	struct tls_handle_t *tls_handle = (struct tls_handle_t *)sess_ctx;
	TEE_Result err;
	
	(void)&params;
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE);

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;
	
	DMSG("TA_TLS_CLOSE");

    mbedtls_ssl_close_notify( &tls_handle->ssl );

	err = socket_handler_close(&tls_handle->socket_sess);

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

	err = socket_handler_open(&tls_handle->socket_sess, params[1].memref.buffer, \
					params[1].memref.size, params[0].value.a);
	
	if( err != TEE_SUCCESS) {
		EMSG("Socket open failed");
		return err;
	}
	
	initialize_tls_structures(&tls_handle->ssl, &tls_handle->conf, \
			&tls_handle->entropy, &tls_handle->ctr_drbg, tls_handle->cacert);

	if(initialize_ctr_drbg(&tls_handle->entropy, &tls_handle->ctr_drbg, "tls_test") != 0) {
		goto exit;
    }
	if(set_ca_root_certificate(tls_handle->cacert, (const unsigned char *) lisha_ca_crt, lisha_ca_crt_len ) != 0) {
		goto exit;
    }
    if(setting_up_tls(&tls_handle->conf, &tls_handle->ctr_drbg, tls_handle->cacert) != 0) {
		goto exit;
    }
    if(assign_configuration(&tls_handle->ssl, &tls_handle->conf) != 0) {
		goto exit;
    }
	if(set_hostname( &tls_handle->ssl, (const char *) params[1].memref.buffer ) != 0) {
		goto exit;
    }
	set_bio(&tls_handle->ssl, &tls_handle->socket_sess, f_send, f_recv, NULL);
    if(handshake(&tls_handle->ssl) != 0) {
		goto exit;
    }
    if(verify_server_certificate(&tls_handle->ssl) != 0) {
		goto exit;
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

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	struct buffer_t encrypted_data;
	struct buffer_t plain_data;
	struct crypto_header_t header;
	struct buffer_t iv;
	unsigned char type_data;
	
	uint32_t header_size = sizeof(header);
	
	unsigned char * pointer = (unsigned char*) params[0].memref.buffer;
	
	memcpy(&header, pointer, header_size);
	pointer += header_size -1;
	
	memcpy(&type_data, pointer, 1);
	pointer += 1;
	
	encrypted_data.buffer = pointer;
	encrypted_data.buffer_size = header.encrypted_size;
	
	iv.buffer = header.iv;
	iv.buffer_size = sizeof(header.iv);

	decrypt_data(&tls_handle->cipher, &iv, \
                &encrypted_data, &plain_data);

	type_data = plain_data.buffer[0];
	if(type_data == ((unsigned char) 'S')) {
		type_data = SERIE;
	} else {
		if (type_data == ((unsigned char) 'R')) {
			type_data = RECORD;
		} else {
			free(plain_data.buffer);
			return TEE_ERROR_CANCEL;
		}
	}

	char buffer_out[512];
    memset(buffer_out, 0, 512);
	int size = mount_request( buffer_out, 512, tls_handle->httpHeader, type_data, (plain_data.buffer+1), tls_handle->credentials);
    
	DMSG("\n mount_request:\n%s\n", buffer_out);

	params[1].value.a = 0;
	ret = tls_handler_write(&tls_handle->ssl, (unsigned char *) buffer_out, size);

	free(plain_data.buffer);

	if(ret <  0)
		return TEE_ERROR_COMMUNICATION;
	
	params[1].value.a = ret;

	return TEE_SUCCESS;
}

static TEE_Result ta_tls_recv(void *sess_ctx, uint32_t param_types,
	TEE_Param params[4])
{
	struct tls_handle_t *tls_handle = (struct tls_handle_t *)sess_ctx;
	
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_OUTPUT,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE);

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	params[0].memref.size = tls_handler_read( \
				&tls_handle->ssl, \
				params[0].memref.buffer, \
				params[0].memref.size);
	
	return TEE_SUCCESS;
}

static TEE_Result test_encrypt_data(void *sess_ctx, uint32_t param_types,
	TEE_Param params[4])
{
	struct tls_handle_t *tls_handle = (struct tls_handle_t *)sess_ctx;
	
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_OUTPUT,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE);

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	unsigned char iv_char[16];
	struct buffer_t iv = { .buffer_size = 16, .buffer = iv_char};
	gerate_iv(&iv);

	unsigned char type_data = ((unsigned char) 'S');
	struct Serie serie = { \
				.version = 17, \
				.unit = 2224179556, \
				.x = 741868840, \
				.y = 679816441, \
                .z = 25300, \
				.dev = 0, \
				.r = 0, \
				.t0 = 1567021716000000, \
				.t1 = 1567028916000000 };

	struct crypto_header_t header;
	struct buffer_t data;
	struct buffer_t plain_buffer;
	uint32_t header_size = sizeof(header);
	uint32_t total_size = header_size;

	plain_buffer.buffer_size = sizeof(serie) + 1;
	unsigned char ddata[plain_buffer.buffer_size];
	
	memcpy(ddata, &type_data, 1);
	memcpy(ddata + 1, &serie, sizeof(serie));
	plain_buffer.buffer = ddata;

	create_encrypted_data(&tls_handle->cipher, &iv, \
                &plain_buffer, &data);

	total_size += data.buffer_size;
	if (params[0].memref.size < total_size) {
		free(data.buffer);
		return TEE_ERROR_SHORT_BUFFER;
	}

	header.encrypted_size = data.buffer_size;
	memcpy(header.iv, iv.buffer, iv.buffer_size);

	memcpy(params[0].memref.buffer, &header, header_size);
	memcpy(((unsigned char *) params[0].memref.buffer) + header_size, data.buffer, data.buffer_size);

	params[0].memref.size = total_size;
	free(data.buffer);

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
	case TEST_ENCRYPT_DATA:
		return test_encrypt_data(sess_ctx, param_types, params);
	default:
		return TEE_ERROR_NOT_SUPPORTED;
	}
}