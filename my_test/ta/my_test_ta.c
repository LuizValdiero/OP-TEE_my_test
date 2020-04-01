#include <string.h>
#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>
//#include <tee_api.h>

#include <my_test_ta.h>

#define STREAM_CIPHER_UUID \
	        { 0x59994caf, 0x61db, 0x499d, \
    			        { 0xb3, 0xa2, 0xdc, 0x1d, 0x1f, 0x92, 0x49, 0xf4}}


#define STREAM_CIPHER_CMD_CRYTP128 0

/*
 * Called when the instance of the TA is created. This is the first call in
 * the TA.
 */
TEE_Result TA_CreateEntryPoint(void)
{
	DMSG("has been called");

	return TEE_SUCCESS;
}

/*
 * Called when the instance of the TA is destroyed if the TA has not
 * crashed or panicked. This is the last call in the TA.
 */
void TA_DestroyEntryPoint(void)
{
	DMSG("has been called");
}

/*
 * Called when a new session is opened to the TA. *sess_ctx can be updated
 * with a value to be able to identify this session in subsequent calls to the
 * TA. In this function you will normally do the global initialization for the
 * TA.
 */
TEE_Result TA_OpenSessionEntryPoint(uint32_t param_types,
		TEE_Param __maybe_unused params[4],
		void __maybe_unused **sess_ctx)
{
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE);

	DMSG("has been called");

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	/* Unused parameters */
	(void)&params;
	(void)&sess_ctx;

	/*
	 * The DMSG() macro is non-standard, TEE Internal API doesn't
	 * specify any means to logging from a TA.
	 */
	IMSG("Hello World!\n");

	/* If return value != TEE_SUCCESS the session will not be created. */
	return TEE_SUCCESS;
}

/*
 * Called when a session is closed, sess_ctx hold the value that was
 * assigned by TA_OpenSessionEntryPoint().
 */
void TA_CloseSessionEntryPoint(void __maybe_unused *sess_ctx)
{
	(void)&sess_ctx; /* Unused parameter */
	IMSG("Goodbye!\n");
}

static TEE_Result encrypt128(uint32_t param_types, TEE_Param params[4])
{
	TEE_TASessionHandle sess;
	TEE_Result err;
	uint32_t err_origin;
	//char *key = &aes_ctr_key->key;
	char key[16] = {0x99, 0xF3, 0xCC, 0xA3, 0xFC, 0xC7, 0x10, 0x76, 0xAC, 0x16,
          0x86, 0x41, 0xD9, 0x06, 0xCE, 0xB5};
	//char *iv = &aes_ctr_key->iv;
	char iv[8] = {0x65, 0x04, 0xEF, 0x3F, 0x0D, 0xBF, 0xBE, 0x2A};

	uint32_t exp_param = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT, 
		TEE_PARAM_TYPE_MEMREF_OUTPUT,
		TEE_PARAM_TYPE_NONE,
		TEE_PARAM_TYPE_NONE);

	if (param_types != exp_param)
		return 0x22;
		//return TEE_ERROR_BAD_PARAMETERS;


// TEE_OpenTASession()
// TEE_InvokeTACommand()
// TEE_CloseTASession()

	TEE_UUID uuid = STREAM_CIPHER_UUID;
	err = TEE_OpenTASession(&uuid, TEE_TIMEOUT_INFINITE, 
		NULL, NULL, &sess, &err_origin);
	
	if (err != TEE_SUCCESS)
		return 0x30;


	TEE_Param op[4];
	//op->paramTypes = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
	//				 TEE_PARAM_TYPE_MEMREF_OUTPUT,
	//				 TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE);;

	uint32_t ptypes = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
			TEE_PARAM_TYPE_MEMREF_INPUT,
			TEE_PARAM_TYPE_MEMREF_INPUT,
			TEE_PARAM_TYPE_MEMREF_OUTPUT);

	op[0].memref.buffer = key;
	op[0].memref.size = 16;
	op[1].memref.buffer = iv;
	op[1].memref.size = 8;
	op[2].memref.buffer = params[0].memref.buffer;
	op[2].memref.size = params[0].memref.size;
	op[3].memref.buffer = params[1].memref.buffer;
	op[3].memref.size = params[1].memref.size;

	err = TEE_InvokeTACommand(sess, TEE_TIMEOUT_INFINITE,
		STREAM_CIPHER_CMD_CRYTP128,  
		ptypes,
		op, &err_origin);
	if (err != TEE_SUCCESS)
		return err;

	TEE_CloseTASession(sess);

	return TEE_SUCCESS;
}

static TEE_Result inc_value(uint32_t param_types,
	TEE_Param params[4])
{
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INOUT,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE);

	DMSG("has been called");

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	IMSG("Got value: %u from NW", params[0].value.a);
	params[0].value.a++;
	IMSG("Increase value to: %u", params[0].value.a);

	return TEE_SUCCESS;
}

static TEE_Result dec_value(uint32_t param_types,
	TEE_Param params[4])
{
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INOUT,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE);

	DMSG("has been called");

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	IMSG("Got value: %u from NW", params[0].value.a);
	params[0].value.a--;
	IMSG("Decrease value to: %u", params[0].value.a);

	return TEE_SUCCESS;
}
/*
 * Called when a TA is invoked. sess_ctx hold that value that was
 * assigned by TA_OpenSessionEntryPoint(). The rest of the paramters
 * comes from normal world.
 */
TEE_Result TA_InvokeCommandEntryPoint(void __maybe_unused *sess_ctx,
			uint32_t cmd_id,
			uint32_t param_types, TEE_Param params[4])
{
	(void)&sess_ctx; /* Unused parameter */

	switch (cmd_id) {
	case TA_MY_TEST_CMD_INC_VALUE:
		return inc_value(param_types, params);
	case TA_MY_TEST_CMD_DEC_VALUE:
		return dec_value(param_types, params);
	case TA_MY_TEST_ENCRYPT128:
		return encrypt128(param_types, params);
	default:
		return 0x23;
		//return TEE_ERROR_BAD_PARAMETERS;
	}
}
