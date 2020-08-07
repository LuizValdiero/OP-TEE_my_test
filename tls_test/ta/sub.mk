global-incdirs-y += include
global-incdirs-y += include_ta
srcs-y += src/connections_handler.c
srcs-y += src/crypto.c
srcs-y += src/data_structure/record.c
srcs-y += src/data_structure/serie.c
srcs-y += src/data_handler.c
srcs-y += src/http_handler.c
srcs-y += src/my_post.c
srcs-y += src/serial_package.c
srcs-y += src/socket_handler.c
srcs-$(CFG_TA_MBEDTLS) += src/tls_handler.c
srcs-$(CFG_TA_MBEDTLS) += src/tls_test_ta.c
srcs-y += src/utils/data_version_handler.c
srcs-y += src/utils/double_format_handler.c

libnames += mbedtls
libdirs += $(ta-dev-kit-dir)/lib
libdeps += $(ta-dev-kit-dir)/lib/libmbedtls.a

# To remove a certain compiler flag, add a line like this
#cflags-template_ta.c-y += -Wno-strict-prototypes
