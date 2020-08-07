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
SRCS += src/http_handler.c
SRCS += src/my_post.c
SRCS += src/serial_package.c
SRCS += src/tls_handler.c
SRCS += src/utils/data_version_handler.c
SRCS += src/utils/double_format_handler.c

.PHONY: all my_test libs

all: my_test
	cp -p ./my_test ./host/socket-TCP-test-mbedtls

libs: $(LIBS_DIR)libmbedtls
	@make -C $^

my_test: $(SRCS) libs
	@echo "compile $@"
	@$(CC) $(FLAGS) $(SRCS) $(MBEDTLS_FLAGS) -o $@

.PHONY: clean
clean:
	@echo "clean"
	@rm -rf *.o *~ my_test
