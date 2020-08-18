#include <connections_handler.h>

int send_data(struct test_ctx *ctx, buffer_t * package_in, int * response_code)
{
    uint32_t err_origin;
    TEEC_Result res;
	TEEC_Operation op;
	
	memset(&op, 0, sizeof(op));
    op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, TEEC_VALUE_OUTPUT, \
                TEEC_NONE, TEEC_NONE);
    op.params[0].tmpref.buffer = package_in->buffer;
    op.params[0].tmpref.size = package_in->buffer_size;
    op.params[1].value.a = 0;
    *response_code = 0;

    res = TEEC_InvokeCommand(&ctx->sess, TA_TLS_SEND_CMD, &op, &err_origin);
    if (res != TEEC_SUCCESS)
		return res;

	*response_code = op.params[1].value.a;
    return res;
}

int open_connections(struct test_ctx *ctx, const char * server_addr, int server_addr_size, const int port)
{
	TEEC_UUID uuid = TA_TLS_TEST_UUID;
	uint32_t origin;
	TEEC_Result res;
    TEEC_Operation op;
	
	/* Initialize a context connecting us to the TEE */
	res = TEEC_InitializeContext(NULL, &ctx->ctx);
	if (res != TEEC_SUCCESS)
		return res;

	/* Open a session with the TA */
	res = TEEC_OpenSession(&ctx->ctx, &ctx->sess, &uuid,
			       TEEC_LOGIN_PUBLIC, NULL, NULL, &origin);
	if (res != TEEC_SUCCESS)
		return res;	

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, \
				TEEC_MEMREF_TEMP_INPUT, TEEC_NONE, TEEC_NONE);
	op.params[0].value.a = port;
	op.params[1].tmpref.buffer = (unsigned char *) server_addr;
	op.params[1].tmpref.size = server_addr_size;

	printf("Invoking TA to tls open\n");
	res = TEEC_InvokeCommand(&ctx->sess, TA_TLS_OPEN_CMD, &op, &origin);
    
    return res;
}

int close_conections(struct test_ctx *ctx) {
    uint32_t err_origin;
    TEEC_Result res;
	TEEC_Operation op;
	    
	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_NONE, TEEC_NONE, TEEC_NONE, TEEC_NONE);

	printf("Invoking TA to tls close\n");
	res = TEEC_InvokeCommand(&ctx->sess, TA_TLS_CLOSE_CMD, &op, &err_origin);
	if (res != TEEC_SUCCESS)
		return res;

	TEEC_CloseSession(&ctx->sess);
	TEEC_FinalizeContext(&ctx->ctx);
	return 0;
}