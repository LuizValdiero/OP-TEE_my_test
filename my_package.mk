################################################################################
# MY_PACKAGE
################################################################################

MY_PACKAGE_PATH		?= $(ROOT)/../my_package
BR2_PACKAGE_MY_PACKAGE ?= y
BR2_PACKAGE_MY_PACKAGE_CROSS_COMPILE ?= $(CROSS_COMPILE_S_USER)
BR2_PACKAGE_MY_PACKAGE_SDK ?= $(OPTEE_OS_TA_DEV_KIT_DIR)
BR2_PACKAGE_MY_PACKAGE_SITE ?= $(MY_PACKAGE_PATH)

MY_PACKAGE_COMMON_FLAGS ?= HOST_CROSS_COMPILE=$(CROSS_COMPILE_NS_USER)\
	TA_CROSS_COMPILE=$(CROSS_COMPILE_S_USER) \
	TA_DEV_KIT_DIR=$(OPTEE_OS_TA_DEV_KIT_DIR) \
	TEEC_EXPORT=$(OPTEE_CLIENT_EXPORT)

.PHONY: my-package-common
my-package-common: optee-os optee-client
	$(MAKE) -C $(MY_PACKAGE_PATH) $(MY_PACKAGE_COMMON_FLAGS)

MY_PACKAGE_CLEAN_COMMON_FLAGS ?= TA_DEV_KIT_DIR=$(OPTEE_OS_TA_DEV_KIT_DIR)

.PHONY: my-package-clean-common
my-package-clean-common:
	#$(MAKE) -C $(MY_PACKAGE_PATH) $(MY_PACKAGE_CLEAN_COMMON_FLAGS) clean
