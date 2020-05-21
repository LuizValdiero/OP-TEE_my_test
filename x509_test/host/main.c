#include <err.h>
#include <stdio.h>
#include <string.h>

#include <tee_client_api.h>

#include <x509_test_ta.h>

/* TEE resources */
struct test_ctx {
	TEEC_Context ctx;
	TEEC_Session sess;
};

void prepare_tee_session(struct test_ctx *ctx)
{
	
	TEEC_UUID uuid = TA_X509_TEST_UUID;
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

	printf("begin x509_ctr\n");

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_NONE, TEEC_NONE,
					 TEEC_NONE, TEEC_NONE);

	res = TEEC_InvokeCommand(&ctx.sess, TA_X509_CMD, &op, &err_origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InvokeCommand TA_X509_CMD failed with code 0x%x origin 0x%x",
			res, err_origin);

	printf("finish x509_ctr\n");
	
	TEEC_CloseSession(&ctx.sess);
	TEEC_FinalizeContext(&ctx.ctx);

	return 0;
}
