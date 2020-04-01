#include <err.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* OP-TEE TEE client API (built by optee_client) */
#include <tee_client_api.h>

/* To the the UUID (found the the TA's h-file(s)) */
#include <aes_serial_ta.h>


#define MAX_BUFFER_SIZE 100


static void get_args(int argc, char *argv[], char **plaintext, size_t *text_size)
{
	if (argc != 2) {
		warnx("Unexpected number of arguments %d (expected 1)",
		      argc - 1);
		exit(1);
	}

	*plaintext = argv[1];
	*text_size = strlen(argv[1]);
}

/* TEE resources */
struct test_ctx {
	TEEC_Context ctx;
	TEEC_Session sess;
};

void prepare_tee_session(struct test_ctx *ctx)
{
	TEEC_UUID uuid = TA_AES_SERIAL_UUID;
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

void terminate_tee_session(struct test_ctx *ctx)
{
	TEEC_CloseSession(&ctx->sess);
	TEEC_FinalizeContext(&ctx->ctx);
}


int main(int argc, char *argv[])
{
	struct test_ctx ctx;
	TEEC_Result res;
	uint32_t origin;
	TEEC_Operation op;
	
	char * plaintext;
	char * ciphertext;
	size_t text_size;
	
	get_args(argc, argv, &plaintext, &text_size);
	ciphertext = malloc(text_size);
	if (!ciphertext)
	{
		err(1, "Cannot allocate out buffer of size %zu", text_size);
	}
	prepare_tee_session(&ctx);

	printf("prepare tee session - AES_SERIAL - ok\n");

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
					 TEEC_MEMREF_TEMP_OUTPUT,
					 TEEC_NONE, TEEC_NONE);
	
	op.params[0].tmpref.buffer = plaintext;
	op.params[0].tmpref.size = text_size;
	op.params[1].tmpref.buffer = ciphertext;
	op.params[1].tmpref.size = text_size;

	printf("set params ok\n");

	res = TEEC_InvokeCommand(&ctx.sess, TA_ENCRYPT, &op, &origin);
	
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InvokeCommand(CIPHER) failed 0x%x origin 0x%x",
			res, origin);

	printf("buffer: ");
	uint32_t n = 0;
	for (n = 0; n < op.params[0].tmpref.size; n++)
		printf("%02x ", ((uint8_t *)op.params[0].tmpref.buffer)[n]);
	printf("\n");

	printf("Encrypted buffer: ");
	for (n = 0; n < op.params[1].tmpref.size; n++)
		printf("%02x ", ((uint8_t *)op.params[1].tmpref.buffer)[n]);
	printf("\n");

	printf("ENCRYPT message (%i): < %s >\n", op.params[1].tmpref.size, ciphertext );

	free(ciphertext);

	terminate_tee_session(&ctx);
	return 0;
}
