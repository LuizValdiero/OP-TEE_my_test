
#include "socket_handler.h"
#include "../../socket_test/ta/include/socket_test_ta.h"

#include <string.h>

TEE_UUID uuid_socket = TA_SOCKET_TEST_UUID;


TEE_Result socket_handler_open(TEE_TASessionHandle *sess, uint32_t param_types,
	TEE_Param params[4])
{
    TEE_Result res;
	uint32_t err_origin;

    res = TEE_OpenTASession(&uuid_socket, TEE_TIMEOUT_INFINITE, 
		0, NULL, sess, &err_origin);
	
	if (res != TEE_SUCCESS)
	{
		EMSG("socket_test openTaSession error");
		return res;
	}

	res = TEE_InvokeTACommand(*sess, TEE_TIMEOUT_INFINITE,
		TA_SOCKET_OPEN_CMD,  
		param_types,
		params, &err_origin);
	
    return res;
}

TEE_Result socket_handler_close(TEE_TASessionHandle *sess, uint32_t param_types,
	TEE_Param params[4])
{
    TEE_Result res;
	uint32_t err_origin;

	res = TEE_InvokeTACommand(*sess, TEE_TIMEOUT_INFINITE, \
                TA_SOCKET_CLOSE_CMD, \
                param_types, \
                params, &err_origin);

    if(res != TEE_SUCCESS)
        return res;
	
    TEE_CloseTASession(*sess);
    return res;
}


int f_send(void * sess_ctx, const unsigned char * buf, unsigned int len)
{
	DMSG("has been called\n");
	TEE_TASessionHandle * sess = (TEE_TASessionHandle *)sess_ctx;
	TEE_Result err;
	uint32_t err_origin;

	TEE_Param op[4];
	memset(&op, 0, sizeof(op));
	op[0].memref.buffer = (unsigned char *) buf;
	op[0].memref.size = len;

	uint32_t ptypes = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
						   TEE_PARAM_TYPE_VALUE_OUTPUT,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE);
	
	err = TEE_InvokeTACommand( *sess, TEE_TIMEOUT_INFINITE,
		TA_SOCKET_SEND_CMD,  
		ptypes,
		op, &err_origin);
	
	DMSG("\n  . f_send sent %d bytes, res: %x\n", op[1].value.a, err);
		
	if (err != TEE_SUCCESS)
	{
		EMSG("\n  . Error 0x%x", err);
		return err;
	}
	return op[1].value.a;
}

int f_recv(void * sess_ctx, unsigned char * buf, unsigned int len)
{
	DMSG("has been called");
	TEE_TASessionHandle * sess = (TEE_TASessionHandle *)sess_ctx;
	TEE_Result err;
	uint32_t err_origin;

	TEE_Param op[4];
	memset(&op, 0, sizeof(op));
	op[0].memref.buffer = buf;
	op[0].memref.size = len;

	uint32_t ptypes = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_OUTPUT,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE);
	
	err = TEE_InvokeTACommand( *sess, TEE_TIMEOUT_INFINITE,
		TA_SOCKET_RECV_CMD,  
		ptypes,
		op, &err_origin);
	if (err != TEE_SUCCESS)
	{
		EMSG("\n  . Error 0x%x", err);
		return err;
	}

	return op[0].memref.size;
}
