global-incdirs-y += include
srcs-y += tls_test_ta.c

libnames += mbedtls
libdirs += lib/libmbedtls
libdeps += $(ta-dev-kit-dir)/lib/libmbedtls.a

# To remove a certain compiler flag, add a line like this
#cflags-template_ta.c-y += -Wno-strict-prototypes
