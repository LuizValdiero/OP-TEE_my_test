#include <socket_handler.h>

#include <string.h>

TEE_UUID uuid_pta_socket = PTA_SOCKET_UUID;


TEE_Result socket_handler_initialize(void *sess_ctx) {
	struct socket_handle_t *socket_handle = (struct socket_handle_t *)sess_ctx;
	socket_handle->socket_handle = 0;
	TEE_Result res;
	uint32_t err_origin;

	res = TEE_OpenTASession(&uuid_pta_socket, TEE_TIMEOUT_INFINITE, \
					0, NULL, &socket_handle->sess, &err_origin);
	
	if (res != CODE_SUCCESS)
	{
		EMSG("socket_test openTaSession error");
		return res;
	}

	return CODE_SUCCESS;
}

void socket_handler_finish(void *sess_ctx) {
	struct socket_handle_t *socket_handle = (struct socket_handle_t *)sess_ctx;
	TEE_CloseTASession(socket_handle->sess);
}


TEE_Result socket_handler_open(void *sess_ctx, \
				unsigned char * server, size_t server_len, uint32_t port)
{
    struct socket_handle_t *socket_handle = (struct socket_handle_t *)sess_ctx;
	TEE_Result res;
	uint32_t err_origin;

	uint32_t ptypes = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
						TEE_PARAM_TYPE_MEMREF_INPUT,
						TEE_PARAM_TYPE_VALUE_INPUT,
						TEE_PARAM_TYPE_VALUE_OUTPUT);

	TEE_Param op[4];
	memset(&op, 0, sizeof(op));
	op[0].value.a = TEE_IP_VERSION_4;
	op[0].value.b = port;
	op[1].memref.buffer = server;
	op[1].memref.size = server_len;
	op[2].value.a = TEE_ISOCKET_PROTOCOLID_TCP;

	res = TEE_InvokeTACommand(socket_handle->sess, TEE_TIMEOUT_INFINITE,
		PTA_SOCKET_OPEN,  
		ptypes,
		op, &err_origin);
	
	socket_handle->socket_handle = op[3].value.a;

    return res;
}

TEE_Result socket_handler_close(void *sess_ctx)
{
    struct socket_handle_t *socket_handle = (struct socket_handle_t *)sess_ctx;
	TEE_Result res;
	uint32_t err_origin;


	uint32_t ptypes = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_NONE);

	TEE_Param op[4];
	memset(&op, 0, sizeof(op));
	op[0].value.a = socket_handle->socket_handle;
	
	res = TEE_InvokeTACommand(socket_handle->sess, TEE_TIMEOUT_INFINITE, \
                PTA_SOCKET_CLOSE, \
                ptypes, \
                op, &err_origin);

    if(res != CODE_SUCCESS)
        return res;
	
    return res;
}


int f_send(void * sess_ctx, const unsigned char * buf, unsigned int len)
{
    struct socket_handle_t *socket_handle = (struct socket_handle_t *)sess_ctx;
	
	TEE_Result err;
	uint32_t err_origin;

	TEE_Param op[4];
	memset(&op, 0, sizeof(op));
	op[0].value.a = socket_handle->socket_handle;
	op[0].value.b = TEE_TIMEOUT_INFINITE;
	op[1].memref.buffer = (unsigned char *) buf;
	op[1].memref.size = len;
	
	uint32_t ptypes = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
						TEE_PARAM_TYPE_MEMREF_INPUT,
						TEE_PARAM_TYPE_VALUE_OUTPUT,
						TEE_PARAM_TYPE_NONE);

	err = TEE_InvokeTACommand( socket_handle->sess, TEE_TIMEOUT_INFINITE,
		PTA_SOCKET_SEND,  
		ptypes,
		op, &err_origin);

	if (err != CODE_SUCCESS)
	{
		EMSG("\n  . Error 0x%x", err);
		return err;
	}
	return op[2].value.a;
}

int f_recv_timeout(void * sess_ctx, unsigned char * buf, unsigned int len,  uint32_t timeout)
{
    struct socket_handle_t *socket_handle = (struct socket_handle_t *)sess_ctx;

	TEE_Result err;
	uint32_t err_origin;

	if(!timeout)
		timeout = TEE_TIMEOUT_INFINITE;

	TEE_Param op[4];
	memset(&op, 0, sizeof(op));
	
	op[0].value.a = socket_handle->socket_handle;
	op[0].value.b = timeout;
	op[1].memref.buffer = buf;
	op[1].memref.size = len;

	uint32_t ptypes = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
						TEE_PARAM_TYPE_MEMREF_OUTPUT,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_NONE);
	
	err = TEE_InvokeTACommand( socket_handle->sess, TEE_TIMEOUT_INFINITE,
		PTA_SOCKET_RECV,  
		ptypes,
		op, &err_origin);

	if (err != CODE_SUCCESS)
	{
		EMSG("\n  . Error 0x%x", err);
		return err;
	}

	return op[1].memref.size;
}


int f_recv(void * sess_ctx, unsigned char * buf, unsigned int len)
{
	return f_recv_timeout( sess_ctx, buf, len, TEE_TIMEOUT_INFINITE);

}
