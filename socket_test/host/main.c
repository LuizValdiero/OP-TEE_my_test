#include <err.h>
#include <stdio.h>
#include <string.h>

#include <tee_client_api.h>

#include <socket_test_ta.h>


/* TEE resources */
struct test_ctx {
	TEEC_Context ctx;
	TEEC_Session sess;
};

void prepare_tee_session(struct test_ctx *ctx)
{
	
	TEEC_UUID uuid = TA_SOCKET_TEST_UUID;
	uint32_t origin;
	TEEC_Result res;

	/* Initialize a context connecting us to the TEE */
	res = TEEC_InitializeContext(NULL, &ctx->ctx);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InitializeContext failed with code 0x%x", res);

	/* Open a session with the TA */
	res = TEEC_OpenSession(&ctx->ctx, &ctx->sess, &uuid,
			       TEEC_LOGIN_PUBLIC, NULL, NULL, &origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_Opensession failed with code 0x%x origin 0x%x",
			res, origin);
}

int main(void)
{
	struct test_ctx ctx;
	TEEC_Result res;
	TEEC_Operation op;
	uint32_t err_origin;

	prepare_tee_session(&ctx);

// --------------------------- //
//      Open Connection TCP/IP
// --------------------------- //

	char server_addr[255] = "10.0.0.4";
	
	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_MEMREF_TEMP_INPUT,
					 TEEC_NONE, TEEC_NONE);
	op.params[0].value.a = 4433;
	op.params[1].tmpref.buffer = server_addr;
	op.params[1].tmpref.size = sizeof(server_addr);

	printf("server %s:%d\n", server_addr, op.params[0].value.a);

	printf("Invoking TA to socket open\n");
	res = TEEC_InvokeCommand(&ctx.sess, TA_SOCKET_OPEN_CMD, &op, &err_origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x",
			res, err_origin);


// --------------------------- //
//      Send Message "Hello World"
// --------------------------- //

	char msg[] = "Hello World";
	printf("message (%d bytes): %s\n", strlen(msg), msg);

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
					 TEEC_VALUE_OUTPUT, TEEC_NONE, TEEC_NONE);
	op.params[0].tmpref.buffer = msg;
	op.params[0].tmpref.size = strlen(msg);

	printf("Invoking TA to socket send\n");
	res = TEEC_InvokeCommand(&ctx.sess, TA_SOCKET_SEND_CMD, &op, &err_origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x",
			res, err_origin);

	printf("%d Bytes sent\n\n", op.params[1].value.a);

// --------------------------- //
//      Recv Message
// --------------------------- //

	char msg_received[100];
	memset(msg_received, 0x0, sizeof(msg_received));

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_OUTPUT,
					  TEEC_NONE, TEEC_NONE, TEEC_NONE);
	op.params[0].tmpref.buffer = msg_received;
	op.params[0].tmpref.size = sizeof(msg_received);

	printf("Invoking TA to socket recv\n");
	res = TEEC_InvokeCommand(&ctx.sess, TA_SOCKET_RECV_CMD, &op, &err_origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x",
			res, err_origin);
	printf("message received (%d bytes): %s\n\n", op.params[0].tmpref.size, msg_received);

// --------------------------- //
//      Close connection
// --------------------------- //

	memset(&op, 0, sizeof(op));

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_NONE, TEEC_NONE, TEEC_NONE, TEEC_NONE);

	printf("Invoking TA to socket close\n");
	res = TEEC_InvokeCommand(&ctx.sess, TA_SOCKET_CLOSE_CMD, &op, &err_origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x",
			res, err_origin);

	printf("Connection closed\n");

// ------------------------------ //

	TEEC_CloseSession(&ctx.sess);

	TEEC_FinalizeContext(&ctx.ctx);

	return 0;
}
