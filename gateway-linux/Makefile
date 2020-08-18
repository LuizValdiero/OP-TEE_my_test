CC := $(CROSS_COMPILE)gcc

LIBS_DIR = ./libs/
FLAGS = -Wall -Wextra  -O2 -static
MBEDTLS_FLAGS = -I$(LIBS_DIR) -D_FILE_OFFSET_BITS=64 -L$(LIBS_DIR) -lmbedtls -lmbedx509 -lmbedcrypto

SRCS = src/main.c

SRCS += src/crypto.c
SRCS += src/connections_handler.c
SRCS += src/data_structure/record.c
SRCS += src/data_structure/serie.c
SRCS += src/data_handler.c
SRCS += src/serial_package.c
SRCS += src/utils/data_version_handler.c
SRCS += src/utils/double_format_handler.c

.PHONY: all gateway-linux libs

all: gateway-linux
	cp -p ./gateway-linux ./host/gateway-linux

libs: $(LIBS_DIR)libmbedtls
	@make -C $^

my_test_mbedtls: $(SRCS) libs
	@echo "compile $@"
	@$(CC) $(FLAGS) $(SRCS) $(MBEDTLS_FLAGS) -o $@

.PHONY: clean
clean:
	@echo "clean"
	@rm -rf *.o *~ gateway-linux
