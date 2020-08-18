#ifndef CONNECTIONS_HANDLER_H
#define CONNECTIONS_HANDLER_H

#include <unistd.h>
#include <string.h>

#include <defines.h>

#include <tls_test_ta.h>

/* TEE resources */
struct test_ctx {
	TEEC_Context ctx;
	TEEC_Session sess;
};

int send_data(struct test_ctx *ctx, buffer_t * package_in, int * response_code);

int open_connections(struct test_ctx *ctx, const char * server_addr, int server_addr_size, const int port);

int close_conections(struct test_ctx *ctx);

#endif // CONNECTIONS_HANDLER_H