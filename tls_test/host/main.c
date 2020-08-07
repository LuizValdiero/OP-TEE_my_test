#include <err.h>
#include <stdio.h>
#include <string.h>

#include <tee_client_api.h>

#include <tls_test_ta.h>
#include "time_handler.h"

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

	char server_addr[200] = HOSTNAME;
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
	op.params[1].value.a = 1;
	printf("Invoking TA to encrypt data\n");
	res = TEEC_InvokeCommand(&ctx.sess, TEST_ENCRYPT_DATA, &op, &err_origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InvokeCommand TEST_ENCRYPT_DATA failed with code 0x%x origin 0x%x",
			res, err_origin);

	int encrypted_data_size = op.params[0].tmpref.size;

/*
// --------------------------- //
//      Send Data
// --------------------------- //
	
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

//--------------------

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

//--------------------

	memset(encrypted_data, 0x0, BUFFER_LENGTH);
	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_OUTPUT,
					  TEEC_VALUE_INPUT, TEEC_NONE, TEEC_NONE);
	op.params[0].tmpref.buffer = encrypted_data;
	op.params[0].tmpref.size = BUFFER_LENGTH;
	op.params[1].value.a = 0;
	printf("Invoking TA to encrypt data\n");
	res = TEEC_InvokeCommand(&ctx.sess, TEST_ENCRYPT_DATA, &op, &err_origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InvokeCommand TEST_ENCRYPT_DATA failed with code 0x%x origin 0x%x",
			res, err_origin);
*/
#define VALUES_LIST_SIZE 30

//--------------------
	uint64_t sum_time_interval = 0;
	int num_interval = 0;

    uint64_t timest0[VALUES_LIST_SIZE];
	uint64_t timest1[VALUES_LIST_SIZE];

	uint64_t timestamp_usec0;
	uint64_t timestamp_usec1; /* timestamp in microsecond */
		
	for (int i = 0; i < VALUES_LIST_SIZE; i++) {
		
		timestamp_usec0 = get_time_usec();
		
		memset(&op, 0, sizeof(op));
		op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, TEEC_VALUE_OUTPUT, \
					TEEC_NONE, TEEC_NONE);
		op.params[0].tmpref.buffer = encrypted_data;
		op.params[0].tmpref.size = encrypted_data_size;
		op.params[1].value.a = 0;

		res = TEEC_InvokeCommand(&ctx.sess, TA_TLS_SEND_CMD, &op, &err_origin);
		if (res != TEEC_SUCCESS)
			errx(1, "TEEC_InvokeCommand TA_TLS_SEND_CMD failed with code 0x%x origin 0x%x",
				res, err_origin);

		timestamp_usec1 = get_time_usec();
		sum_time_interval += timestamp_usec1 - timestamp_usec0;
        timest0[i] = timestamp_usec0;
        timest1[i] = timestamp_usec1;
        num_interval++;
	}

	FILE * fp;
	
    fp = fopen ("/home/timestamps_send_TEE.txt","w");
	printf("\n fp: %d", (int) fp);
    
	fprintf(fp, "\nnum_interval,media(us)");
	fprintf(fp, "\n%d, %llu", num_interval, sum_time_interval/num_interval);
    fprintf(fp, "\nenvio, t0(us), t1(us)");
	
	for (int i = 0; i < VALUES_LIST_SIZE; ++i)
    {
        fprintf(fp, "\n%d, %llu, %llu", i, timest0[i], timest1[i]);
    }
	fclose (fp);

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
