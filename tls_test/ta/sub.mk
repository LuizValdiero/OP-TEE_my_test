global-incdirs-y += include
global-incdirs-y += include_ta
srcs-$(CFG_TA_MBEDTLS) += src/crypto.c
srcs-$(CFG_TA_MBEDTLS) += src/data_structure/record.c
srcs-$(CFG_TA_MBEDTLS) += src/data_structure/serie.c
srcs-$(CFG_TA_MBEDTLS) += src/data_handler.c
srcs-$(CFG_TA_MBEDTLS) += src/http_handler.c
srcs-$(CFG_TA_MBEDTLS) += src/my_post.c
srcs-$(CFG_TA_MBEDTLS) += src/serial_package.c
srcs-$(CFG_TA_MBEDTLS) += src/socket_handler.c
srcs-$(CFG_TA_MBEDTLS) += src/tls_handler.c
srcs-$(CFG_TA_MBEDTLS) += src/tls_test_ta.c
srcs-$(CFG_TA_MBEDTLS) += src/utils/data_version_handler.c

libnames += mbedtls
libdirs += $(ta-dev-kit-dir)/lib
libdeps += $(ta-dev-kit-dir)/lib/libmbedtls.a

# To remove a certain compiler flag, add a line like this
#cflags-template_ta.c-y += -Wno-strict-prototypes
