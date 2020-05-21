#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>

//#include <tee_ipsocket.h>
#include <pta_socket.h>

#include <tee_isocket.h>
#include <tee_tcpsocket.h>

#include <socket_test_ta.h>

struct socket_handle_t {
	int socket_handle;
	TEE_TASessionHandle sess;
};

TEE_UUID uuid = PTA_SOCKET_UUID;

TEE_Result TA_CreateEntryPoint(void)
{
	DMSG(" socket_test");

	return TEE_SUCCESS;
}

void TA_DestroyEntryPoint(void)
{
	DMSG(" socket_test");
}

TEE_Result TA_OpenSessionEntryPoint(uint32_t param_types,
		TEE_Param __maybe_unused params[4],
		void __maybe_unused **sess_ctx)
{
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE);
	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	/* Unused parameters */
	(void)&params;

	struct socket_handle_t *socket_handle;
	
	socket_handle = TEE_Malloc(sizeof(struct socket_handle_t *), 0);
	if (!socket_handle)
		return TEE_ERROR_OUT_OF_MEMORY;

	socket_handle->socket_handle = 0;
	*sess_ctx = (void *)socket_handle;

	DMSG(" socket_test");
	return TEE_SUCCESS;
}

void TA_CloseSessionEntryPoint(void __maybe_unused *sess_ctx)
{
	struct socket_handle_t *socket_handle = (struct socket_handle_t *)sess_ctx;
	TEE_Free(socket_handle);

	DMSG(" socket_test");
}


static TEE_Result socket_open(void *sess_ctx, uint32_t param_types,
	TEE_Param params[4])
{
	struct socket_handle_t *socket_handle = (struct socket_handle_t *)sess_ctx;
	TEE_Result err;
	uint32_t err_origin;

	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
						   TEE_PARAM_TYPE_MEMREF_INPUT,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE);

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	err = TEE_OpenTASession(&uuid, TEE_TIMEOUT_INFINITE, 
		0, NULL, &socket_handle->sess, &err_origin);
	
	if (err != TEE_SUCCESS)
		return err;

	TEE_Param op[4];

	uint32_t ptypes = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
						TEE_PARAM_TYPE_MEMREF_INPUT,
						TEE_PARAM_TYPE_VALUE_INPUT,
						TEE_PARAM_TYPE_VALUE_OUTPUT);

	op[0].value.a = TEE_IP_VERSION_4;
	op[0].value.b = params[0].value.a;
	op[1].memref.buffer = params[1].memref.buffer;
	op[1].memref.size = params[1].memref.size;
	op[2].value.a = TEE_ISOCKET_PROTOCOLID_TCP;
	
	DMSG("\n  Open connection %s:%d",
		(char *) params[1].memref.buffer,
		params[0].value.a);


	err = TEE_InvokeTACommand(socket_handle->sess, TEE_TIMEOUT_INFINITE,
		PTA_SOCKET_OPEN,  
		ptypes,
		op, &err_origin);
	if (err != TEE_SUCCESS)
		return err;

	socket_handle->socket_handle = op[3].value.a;

	DMSG("\n  Success %s:%d, socket_handle: %d\n",
		(char *) params[1].memref.buffer,
		params[0].value.a,
		socket_handle->socket_handle);

	return TEE_SUCCESS;
}

static TEE_Result socket_close(void *sess_ctx, uint32_t param_types,
	TEE_Param params[4])
{
	struct socket_handle_t *socket_handle = (struct socket_handle_t *)sess_ctx;
	TEE_Result err;
	uint32_t err_origin;

	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE);
	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;
	/* Unused parameters */
	(void)&params;

	uint32_t ptypes = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_NONE);

	TEE_Param op[4];
	op[0].value.a = socket_handle->socket_handle;
	
	DMSG("\n  socket_handle: %d", socket_handle->socket_handle);

	err = TEE_InvokeTACommand(socket_handle->sess, TEE_TIMEOUT_INFINITE,
		PTA_SOCKET_CLOSE,  
		ptypes,
		op, &err_origin);
	if (err != TEE_SUCCESS)
		return err;

	TEE_CloseTASession(socket_handle->sess);
	// ??? sera q eu zero ou mantenho
	//socket_handle->socket_handle = 0;

	return TEE_SUCCESS;
}

static TEE_Result socket_send(void *sess_ctx, uint32_t param_types,
	TEE_Param params[4])
{
	struct socket_handle_t *socket_handle = (struct socket_handle_t *)sess_ctx;
	TEE_Result err;
	uint32_t err_origin;

	DMSG(" socket_test socket_send\n");

	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
						   TEE_PARAM_TYPE_VALUE_OUTPUT,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE);

	DMSG("has been called");

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;
	//return 0x1111; //test

	TEE_Param op[4];

	uint32_t ptypes = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
						TEE_PARAM_TYPE_MEMREF_INPUT,
						TEE_PARAM_TYPE_VALUE_OUTPUT,
						TEE_PARAM_TYPE_NONE);

	op[0].value.a = socket_handle->socket_handle;
	op[0].value.b = TEE_TIMEOUT_INFINITE;
	op[1].memref.buffer = params[0].memref.buffer;
	op[1].memref.size = params[0].memref.size;

	DMSG("\n  send(%d bytes): %s", params[0].memref.size, (char *) params[0].memref.buffer);

	err = TEE_InvokeTACommand(socket_handle->sess, TEE_TIMEOUT_INFINITE,
		PTA_SOCKET_SEND,  
		ptypes,
		op, &err_origin);
	if (err != TEE_SUCCESS)
		return err;

	params[1].value.a = op[2].value.a;

	return TEE_SUCCESS;
}

static TEE_Result socket_recv(void *sess_ctx, uint32_t param_types,
	TEE_Param params[4])
{
	struct socket_handle_t *socket_handle = (struct socket_handle_t *)sess_ctx;
	TEE_Result err;
	uint32_t err_origin;

	DMSG(" socket_test socket_recv\n");

	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_OUTPUT,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE);

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	uint32_t ptypes = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
						TEE_PARAM_TYPE_MEMREF_OUTPUT,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_NONE);

	TEE_Param op[4];
	op[0].value.a = socket_handle->socket_handle;
	op[0].value.b = TEE_TIMEOUT_INFINITE;
	op[1].memref.buffer = params[0].memref.buffer;
	op[1].memref.size = params[0].memref.size;
	
	err = TEE_InvokeTACommand(socket_handle->sess, TEE_TIMEOUT_INFINITE,
		PTA_SOCKET_RECV,  
		ptypes,
		op, &err_origin);
	if (err != TEE_SUCCESS)
		return err;

	DMSG("\n  recv(%d bytes): %s", op[1].memref.size, (char *) op[1].memref.buffer);

	return TEE_SUCCESS;
}

static TEE_Result socket_ioctl(void *sess_ctx, uint32_t param_types,
	TEE_Param params[4])
{
	struct socket_handle_t *socket_handle = (struct socket_handle_t *)sess_ctx;
	TEE_Result err;
	uint32_t err_origin;

	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
						   TEE_PARAM_TYPE_MEMREF_INOUT,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE);

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	TEE_Param op[4];

	uint32_t ptypes = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
						TEE_PARAM_TYPE_MEMREF_INOUT,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_NONE);

	op[0].value.a = socket_handle->socket_handle;
	op[0].value.b = params[0].value.a;
	op[1].memref.buffer = params[1].memref.buffer;
	op[1].memref.size = params[1].memref.size;

	err = TEE_InvokeTACommand(socket_handle->sess, TEE_TIMEOUT_INFINITE,
		PTA_SOCKET_IOCTL,  
		ptypes,
		op, &err_origin);
	if (err != TEE_SUCCESS)
		return err;

	return TEE_SUCCESS;
}

TEE_Result TA_InvokeCommandEntryPoint(void __maybe_unused *sess_ctx,
			uint32_t cmd_id,
			uint32_t param_types, TEE_Param params[4])
{
	DMSG("InvokeCommandEntryPoint id:%d", cmd_id);
	switch (cmd_id) {
	case TA_SOCKET_OPEN_CMD:
		return socket_open(sess_ctx, param_types, params);
	case TA_SOCKET_CLOSE_CMD:
		return socket_close(sess_ctx, param_types, params);
	case TA_SOCKET_SEND_CMD:
		return socket_send(sess_ctx, param_types, params);
	case TA_SOCKET_RECV_CMD:
		return socket_recv(sess_ctx, param_types, params);
	case TA_SOCKET_IOCTL_CMD:
		return socket_ioctl(sess_ctx, param_types, params);
	default:
		DMSG(" Socket_test Error\n  ! id:%d not exist", cmd_id);
		return TEE_ERROR_NOT_SUPPORTED;
	}
}
