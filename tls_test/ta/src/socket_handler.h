#ifndef _SOCKET_HANDLER_H
#define _SOCKET_HANDLER_H

#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>


TEE_Result socket_handler_open(TEE_TASessionHandle *sess, uint32_t param_types,
	TEE_Param params[4]);

TEE_Result socket_handler_close(TEE_TASessionHandle *sess, uint32_t param_types,
	TEE_Param params[4]);

int f_send(void * sess_ctx, const unsigned char * buf, unsigned int len);
int f_recv(void * sess_ctx, unsigned char * buf, unsigned int len);

#endif