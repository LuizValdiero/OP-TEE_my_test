#include "./connections_handler.h"
#include "./tls_handler.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>


#include "mbedtls/net_sockets.h"
#include "mbedtls/debug.h"
#include "mbedtls/ssl.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/error.h"
#include "mbedtls/certs.h"

struct connections_handle_t {
    const char * server_addr;
    int port;
    const char * hostname;

    struct sockaddr_in server;
    int sockfd;

	mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_ssl_context ssl; 
    mbedtls_ssl_config conf;
    mbedtls_x509_crt * cacert;

    mbedtls_ssl_session ssl_sess;
} connection;

int reconnect() {
    if (tls_is_connected(&connection.ssl))
        return 0;

    open_tcp(&connection.sockfd, &connection.server, \
                connection.server_addr, connection.port);
    
    return tls_reconnect(&connection.ssl, &connection.ssl_sess);
}

int send_data(unsigned char * buffer, size_t len) {
    if(reconnect())
        return 0;
    return tls_handler_write(&connection.ssl, buffer, len);
}
int recv_data(unsigned char * buffer, size_t len) {
    
    int ret = reconnect(); 
    if(ret)
        return ret;
    
    ret = tls_handler_read(&connection.ssl, buffer, len);
    return ret;
}

int open_connections(const char * server_addr, const int port, const char * hostname, const char * ca_crt, size_t ca_crt_len)
{
    int ret;
    connection.server_addr = server_addr;
    connection.port = port;
    connection.hostname = hostname;

    ret = open_tcp(&connection.sockfd, &connection.server, server_addr, port);

    if(!ret) {
        ret = open_tls((void *) &connection, hostname, ca_crt, ca_crt_len);
        if (!ret)
            return 0;
    }
    
    clear_structs((void *) &connection);
    return 1;
}

int open_tcp(int * sockfd, struct sockaddr_in * server, \
                const char * server_addr, const int port)
{
    *sockfd = socket( AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (*sockfd == -1)
    {
        perror("Socket ");
        return 1;
    }
    struct hostent *hostStructure = gethostbyname(server_addr);
    
    //printf("Socket open - host name: %s\n", hostStructure->h_name);
    server->sin_family       = AF_INET;
    server->sin_port         = htons(port);
    
    struct in_addr ** addr_list = (struct in_addr **)hostStructure->h_addr_list;
    //for(int i = 0; addr_list[i] != NULL; i++) {
    //    printf("%s \n", inet_ntoa(*addr_list[i]));
    //}
    for (int  i = 0; addr_list[i] != NULL; i++) {
        //printf("hostStructure->h_addr_list[%d]: %s\n", i, inet_ntoa(*addr_list[i]));
        server->sin_addr = *addr_list[i];

        memset(server->sin_zero, 0x0, 8);
        if (connect(*sockfd, (struct sockaddr*) server, sizeof(*server)) == -1)
        {
            perror("Error connecting to the server");
            return 1;
        } else {
            return 0;
        }
    }
    return 1;
}

int open_tls(void * connection_struct, const char * hostname, const char * ca_crt, size_t ca_crt_len)
{
    struct connections_handle_t * connection = (struct connections_handle_t *) connection_struct;
    int ret;

    connection->cacert =  malloc(sizeof(mbedtls_x509_crt));

    initialize_tls_structures(&connection->ssl, &connection->ssl_sess, &connection->conf, \
			&connection->entropy, &connection->ctr_drbg, connection->cacert);

    ret = initialize_ctr_drbg(&connection->entropy, &connection->ctr_drbg, "tls_test", mbedtls_entropy_func);
	if(ret != 0) {
		return ret;
    }
	ret = set_ca_root_certificate(connection->cacert, (const unsigned char *) ca_crt, ca_crt_len );
    if(ret != 0) {
		return ret;
    }
	ret = setting_up_tls(&connection->conf, &connection->ctr_drbg, connection->cacert, mbedtls_ctr_drbg_random);
    if(ret != 0) {
		return ret;
    }
	ret = assign_configuration(&connection->ssl, &connection->conf);
    if(ret != 0) {
		return ret;
    }
	ret = set_hostname( &connection->ssl, hostname);
    if(ret != 0) {
		return ret;
    }
    
	set_bio(&connection->ssl, &connection->sockfd, mbedtls_net_send, mbedtls_net_recv, NULL);
    
    mbedtls_ssl_get_session(&connection->ssl, &connection->ssl_sess);
    ret = handshake(&connection->ssl);
    if(ret != 0) {
		return ret;
    }
	ret = verify_server_certificate(&connection->ssl);
    //mbedtls_ssl_close_notify( &connection->ssl);
    return ret;
}

void close_conections() {
    mbedtls_ssl_close_notify( &connection.ssl);
    clear_structs((void *) &connection);
}

void clear_structs(void * connection_struct){
    struct connections_handle_t * connection = (struct connections_handle_t *) connection_struct;
    
    mbedtls_ssl_free( &connection->ssl );
    mbedtls_ssl_config_free( &connection->conf );
    mbedtls_ctr_drbg_free( &connection->ctr_drbg );
    mbedtls_entropy_free( &connection->entropy );
    mbedtls_ssl_session_free(&connection->ssl_sess);

    mbedtls_x509_crt_free( connection->cacert );
    free(connection->cacert);
    
    close(connection->sockfd);
}
