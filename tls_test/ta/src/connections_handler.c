
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include "connections_handler.h"
#include "tls_handler.h"
#include "socket_handler.h"


int send_data(struct connections_handle_t * conn, unsigned char * buffer, size_t len)
{
    if(reconnect(conn))
        return 0;
    return tls_handler_write(&conn->ssl, buffer, len);
}

int recv_data(struct connections_handle_t * conn, unsigned char * buffer, size_t len)
{    
    int ret = reconnect(conn); 
    if(ret)
        return ret;
    
    ret = tls_handler_read(&conn->ssl, buffer, len);
    if(ret == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY) {
        socket_handler_close(&conn->socket_sess);    
    }
    return ret;
}

int reconnect(struct connections_handle_t * conn) {
    if (tls_is_connected(&conn->ssl))
        return 0;
    open_tcp(conn, (unsigned char *) &conn->server_addr, conn->server_addr_size);
    
    return tls_reconnect(&conn->ssl, &conn->ssl_sess);
}


int open_connections(struct connections_handle_t * conn, \
                const char * server_addr, int server_addr_size, \
                const int port, const char * ca_crt, size_t ca_crt_len)
{
    int ret;
    conn->server_addr_size = server_addr_size;
    memcpy(conn->server_addr, server_addr, server_addr_size);
    conn->port = port;

    ret = socket_handler_initialize(&conn->socket_sess);
    if(ret != CODE_SUCCESS) {
        DMSG("\n    ! error to initialize");
        return ret;
    }
    
    ret = open_tcp(conn, (unsigned char *) server_addr, conn->server_addr_size);
    if(ret == CODE_SUCCESS) {
        ret = open_tls(conn, ca_crt, ca_crt_len);
        if (ret == CODE_SUCCESS)
            return ret;
        
        close_conections(conn);
        return ret;
    }
    
    clear_structs(conn);
    return ret;
}

int open_tcp(struct connections_handle_t * conn, \
				unsigned char * server, size_t server_len)
{
    unsigned char buff[200];
    memcpy(buff, server, server_len);
    return socket_handler_open(&conn->socket_sess, (unsigned char *) buff, \
                server_len, conn->port);
}

int open_tls(struct connections_handle_t * conn, \
                const char * ca_crt, size_t ca_crt_len)
{
    initialize_tls_structures(&conn->ssl, &conn->ssl_sess, &conn->conf, \
			&conn->entropy, &conn->ctr_drbg, conn->cacert);

	if(initialize_ctr_drbg(&conn->entropy, &conn->ctr_drbg, "tls_test") != 0) {
		goto exit;
    }
	if(set_ca_root_certificate(conn->cacert, (const unsigned char *) ca_crt, ca_crt_len ) != 0) {
		goto exit;
    }
    if(setting_up_tls(&conn->conf, &conn->ctr_drbg, conn->cacert) != 0) {
		goto exit;
    }
    if(assign_configuration(&conn->ssl, &conn->conf) != 0) {
		goto exit;
    }
	if(set_hostname( &conn->ssl, "iot.lisha.ufsc.br" ) != 0) {
		goto exit;
    }
	set_bio(&conn->ssl, &conn->socket_sess, f_send, f_recv, NULL);
    mbedtls_ssl_get_session(&conn->ssl, &conn->ssl_sess); 
    if(handshake(&conn->ssl) != 0) {
		goto exit;
    }
    if(verify_server_certificate(&conn->ssl) != CODE_SUCCESS) {
		//goto exit;
    }
	return CODE_SUCCESS;

exit:
	return CODE_ERROR_CANCEL; 
}

void close_conections(struct connections_handle_t * conn) {
    mbedtls_ssl_close_notify( &conn->ssl);
    socket_handler_close(&conn->socket_sess);
    socket_handler_finish(&conn->socket_sess);
    clear_structs(conn);
}

void clear_structs(struct connections_handle_t * conn) {
    finish_tls_structures(&conn->ssl, &conn->ssl_sess, &conn->conf, \
                &conn->entropy, &conn->ctr_drbg, conn->cacert);
}