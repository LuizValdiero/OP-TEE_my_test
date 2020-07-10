#include <err.h>
#include <stdio.h>
#include <string.h>

#include <tee_client_api.h>

#include <tls_test_ta.h>

#define HOSTNAME "iot.lisha.ufsc.br"
#define PORT 443
#define BUFFER_LENGTH 2048

/* TEE resources */
struct test_ctx {
	TEEC_Context ctx;
	TEEC_Session sess;
};

void prepare_tee_session(struct test_ctx *ctx)
{
	
	TEEC_UUID uuid = TA_TLS_TEST_UUID;
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
//      Connect to server with SSL/TLS
// --------------------------- //

	char server_addr[255] = HOSTNAME;
	printf("server address: %s\n", server_addr);

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_MEMREF_TEMP_INPUT,
					 TEEC_NONE, TEEC_NONE);
	op.params[0].value.a = PORT;
	op.params[1].tmpref.buffer = server_addr;
	op.params[1].tmpref.size = sizeof(server_addr);

	printf("Invoking TA to tls open\n");
	res = TEEC_InvokeCommand(&ctx.sess, TA_TLS_OPEN_CMD, &op, &err_origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InvokeCommand TA_TLS_OPEN_CMD failed with code 0x%x origin 0x%x",
			res, err_origin);


// --------------------------- //
//      Create Data
// --------------------------- //

	char encrypted_data[BUFFER_LENGTH];
	
	memset(encrypted_data, 0x0, sizeof(encrypted_data));
	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_OUTPUT,
					  TEEC_VALUE_INPUT, TEEC_NONE, TEEC_NONE);
	op.params[0].tmpref.buffer = encrypted_data;
	op.params[0].tmpref.size = sizeof(encrypted_data);
	op.params[1].value.a = 0;
	printf("Invoking TA to encrypt data\n");
	res = TEEC_InvokeCommand(&ctx.sess, TEST_ENCRYPT_DATA, &op, &err_origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InvokeCommand TEST_ENCRYPT_DATA failed with code 0x%x origin 0x%x",
			res, err_origin);


// --------------------------- //
//      Send Data
// --------------------------- //

	int encrypted_data_size = op.params[0].tmpref.size;
	
	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, TEEC_VALUE_OUTPUT, \
				TEEC_NONE, TEEC_NONE);
	op.params[0].tmpref.buffer = encrypted_data;
	op.params[0].tmpref.size = encrypted_data_size;

	printf("Invoking TA to tls send\n");
	res = TEEC_InvokeCommand(&ctx.sess, TA_TLS_SEND_CMD, &op, &err_origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InvokeCommand TA_TLS_SEND_CMD failed with code 0x%x origin 0x%x",
			res, err_origin);

	printf("	. response code: %d\n", op.params[1].value.a);
/*
// --------------------------- //
//      Recv Message
// --------------------------- //

	char msg_received[BUFFER_LENGTH];
	do {
	memset(msg_received, 0x0, sizeof(msg_received));

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_OUTPUT,
					  TEEC_NONE, TEEC_NONE, TEEC_NONE);
	op.params[0].tmpref.buffer = msg_received;
	op.params[0].tmpref.size = sizeof(msg_received);

	printf("Invoking TA to tls recv\n");
	res = TEEC_InvokeCommand(&ctx.sess, TA_TLS_RECV_CMD, &op, &err_origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InvokeCommand TA_TLS_RECV_CMD failed with code 0x%x origin 0x%x",
			res, err_origin);
	printf("message received (%d bytes): %s\n\n", op.params[0].tmpref.size, msg_received);
	} while (op.params[0].tmpref.size > 0);

	memset(msg_received, 0x0, sizeof(msg_received));

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_OUTPUT,
					  TEEC_NONE, TEEC_NONE, TEEC_NONE);
	op.params[0].tmpref.buffer = msg_received;
	op.params[0].tmpref.size = sizeof(msg_received);

	printf("Invoking TA to tls recv\n");
	res = TEEC_InvokeCommand(&ctx.sess, TA_TLS_RECV_CMD, &op, &err_origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InvokeCommand TA_TLS_RECV_CMD failed with code 0x%x origin 0x%x",
			res, err_origin);
	printf("message received (%d bytes): %s\n\n", op.params[0].tmpref.size, msg_received);

// */

// --------------------------- //
//      Close connection
// --------------------------- //

	memset(&op, 0, sizeof(op));

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_NONE, TEEC_NONE, TEEC_NONE, TEEC_NONE);

	printf("Invoking TA to tls close\n");
	res = TEEC_InvokeCommand(&ctx.sess, TA_TLS_CLOSE_CMD, &op, &err_origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InvokeCommand TA_TLS_CLOSE_CMD failed with code 0x%x origin 0x%x",
			res, err_origin);

	printf("Connection closed\n");

// ------------------------------ //

	TEEC_CloseSession(&ctx.sess);

	TEEC_FinalizeContext(&ctx.ctx);

	return 0;
}
