#include <inttypes.h>
#include <serial_test_ta.h>

#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>


static TEE_Result cmd_invert(uint32_t param_types, TEE_Param params[4]) {
	const uint32_t exp_param_types =
		TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
				TEE_PARAM_TYPE_MEMREF_OUTPUT,
				TEE_PARAM_TYPE_NONE,
				TEE_PARAM_TYPE_NONE);	
	
	/* Safely get the invocation parameters */
	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	if (params[1].memref.size != params[0].memref.size) {
		EMSG("Bad sizes: in %d, out %d", params[0].memref.size,
						 params[1].memref.size);
		return TEE_ERROR_BAD_PARAMETERS;
	}
	uint32_t size = params[0].memref.size;
	for (uint32_t i = 0; i < size; i++)
	{
		((char *)params[1].memref.buffer)[size-i-1] = ((char *)params[0].memref.buffer)[i];
		//((char *)params[1].memref.buffer)[i] = ((char *)params[0].memref.buffer)[i];
		//*(((char *)params[1].memref.buffer) + size-i-1) = *(((char *)params[0].memref.buffer) +i);
	}

	return TEE_SUCCESS;
}


TEE_Result TA_CreateEntryPoint(void)
{
	/* Nothing to do */
	return TEE_SUCCESS;
}

void TA_DestroyEntryPoint(void)
{
	/* Nothing to do */
}

TEE_Result TA_OpenSessionEntryPoint(uint32_t __unused param_types,
					TEE_Param __unused params[4],
					void __maybe_unused **session)
{
	(void)&params;
	(void)&session;
	return TEE_SUCCESS;
}

void TA_CloseSessionEntryPoint(void __maybe_unused *session)
{
	(void)&session;
}

TEE_Result TA_InvokeCommandEntryPoint(void __maybe_unused *session, uint32_t cmd,
				      uint32_t param_types,
				      TEE_Param params[4])
{
	(void)&session;
	switch (cmd) {
	case TA_INVERT:
		return cmd_invert( param_types, params);
	default:
		EMSG("Command ID %#" PRIx32 " is not supported", cmd);
		return TEE_ERROR_NOT_SUPPORTED;
	}
}
