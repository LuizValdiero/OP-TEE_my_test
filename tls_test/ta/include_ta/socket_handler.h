#ifndef _SOCKET_HANDLER_H
#define _SOCKET_HANDLER_H

#include <defines.h>

#include <pta_socket.h>
#include <tee_isocket.h>
#include <tee_tcpsocket.h>

struct socket_handle_t {
	int socket_handle;
	TEE_TASessionHandle sess;
};


TEE_Result socket_handler_initialize(void *sess_ctx);

void socket_handler_finish(void *sess_ctx);

TEE_Result socket_handler_open(void *sess_ctx, \
				unsigned char * server, size_t server_len, uint32_t port);

TEE_Result socket_handler_close(void *sess_ctx);

int f_send(void * sess_ctx, const unsigned char * buf, size_t len);
int f_recv(void * sess_ctx, unsigned char * buf, size_t len);
int f_recv_timeout(void * sess_ctx, unsigned char * buf, size_t len,  uint32_t timeout);

#endif // _SOCKET_HANDLER_H