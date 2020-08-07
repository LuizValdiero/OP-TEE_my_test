#ifndef CONNECTIONS_HANDLER_H
#define CONNECTIONS_HANDLER_H

#include <unistd.h>

#include "defines.h"
#include "socket_handler.h"
#include "tls_handler.h"

struct connections_handle_t {
    unsigned char server_addr[200];
    int server_addr_size;
    int port;

	struct socket_handle_t socket_sess;

	mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_ssl_context ssl; 
    mbedtls_ssl_config conf;
    mbedtls_x509_crt * cacert;
    mbedtls_ssl_session ssl_sess;
};


int send_data(struct connections_handle_t * conn, unsigned char * buffer, size_t len);
int recv_data(struct connections_handle_t * conn, unsigned char * buffer, size_t len); 

int reconnect(struct connections_handle_t * conn);


int open_connections(struct connections_handle_t * conn, \
                const char * server_addr, int server_addr_size, \
                const int port, const char * ca_crt, size_t ca_crt_len);

int open_tcp(struct connections_handle_t * conn, \
				unsigned char * server, size_t server_len);
int open_tls(struct connections_handle_t * conn, \
                const char * ca_crt, size_t ca_crt_len);

void close_conections(struct connections_handle_t * conn);
void clear_structs(struct connections_handle_t * conn);

#endif // CONNECTIONS_HANDLER_H