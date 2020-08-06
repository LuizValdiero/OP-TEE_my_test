#ifndef CONNECTIONS_HANDLER_H
#define CONNECTIONS_HANDLER_H

#include <unistd.h>

#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <netdb.h>


int send_data(unsigned char * buffer, size_t len);
int recv_data(unsigned char * buffer, size_t len); 

int open_connections(const char * server_addr, const int port, \
                const char * hostname, const char * ca_crt, size_t ca_crt_len);
int open_tcp(int * sockfd, struct sockaddr_in * server, \
                const char * server_addr, const int port);
int open_tls(void * connection_struct, const char * hostname, \
                const char * ca_crt, size_t ca_crt_len);

void close_conections();
void clear_structs(void * connection_struct);

#endif // CONNECTIONS_HANDLER_H