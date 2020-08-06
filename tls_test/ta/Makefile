CFG_TEE_TA_LOG_LEVEL ?= 1
CPPFLAGS += -DCFG_TEE_TA_LOG_LEVEL=$(CFG_TEE_TA_LOG_LEVEL)


# The UUID for the Trusted Application
BINARY=e7d490f5-0b64-4474-8b3b-c0ed7f3719d3

-include $(TA_DEV_KIT_DIR)/mk/ta_dev_kit.mk

LDFLAGS+= CFG_TA_MBEDTLS

ifeq ($(wildcard $(TA_DEV_KIT_DIR)/mk/ta_dev_kit.mk), )
clean:
	@echo 'Note: $$(TA_DEV_KIT_DIR)/mk/ta_dev_kit.mk not found, cannot clean TA'
	@echo 'Note: TA_DEV_KIT_DIR=$(TA_DEV_KIT_DIR)'
endif
	