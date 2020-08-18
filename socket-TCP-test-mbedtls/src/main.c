#include <sys/time.h>
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>


#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <netdb.h>
/*
#include "mbedtls/net_sockets.h"
#include "mbedtls/debug.h"
#include "mbedtls/ssl.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/error.h"
#include "mbedtls/certs.h"
// */
//*
#include <mbedtls/net_sockets.h>
#include <mbedtls/debug.h>
#include <mbedtls/ssl.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/error.h>
#include <mbedtls/certs.h>
// */
//#include "certs/_.herokuapp.com.pem.h"
#include "../certs/_.lisha.ufsc.br.pem.h"
#include "../credentials/secret_credentials.h"
#include "../credentials/serial_keys.h"

#include "defines.h"
#include "my_post.h"
#include "connections_handler.h"
#include "serial_package.h"
#include "crypto.h"
//
#include "utils/time_handler.h"


#define HOSTNAME "iot.lisha.ufsc.br"
#define PORT 443
#define LEN_BUFFER 2048

unsigned char buffer_in[LEN_BUFFER];
unsigned char buffer_out[LEN_BUFFER];

#define SERVER_ADDR_SIZE 1024
char server_addr[SERVER_ADDR_SIZE];
int port;


#define SERIAL_LIST_SIZE 11
#define VALUES_LIST_SIZE 11

struct serial_data_t {
	unsigned char data[70];
	int len;
} serial_list[SERIAL_LIST_SIZE];
int serial_list_index = -1;

struct values_t {
	uint8_t data_code;
	uint64_t v0;
	uint64_t v1;
} values_list[VALUES_LIST_SIZE];

void get_args(int argc, char ** argv, char * server_addr, int * port) {
    if (argc == 3) {
        *port = atoi(argv[2]);
        memset(server_addr, '\0', SERVER_ADDR_SIZE);
        strcpy(server_addr, argv[1]);
        return;
    }
    memset(server_addr, '\0', SERVER_ADDR_SIZE);
    memcpy(server_addr, HOSTNAME, sizeof(HOSTNAME));
    *port = PORT;
}

int send_package( buffer_t * package_in, int * response_code, \
                struct cipher_handle_t * cipher, \
                struct HttpHeader_t * httpHeader, \
                struct credentials_t * credentials)
{
	int ret;
	
	buffer_t encrypted_data;
	buffer_t plain_data;
	serial_header_t header;
	
	dismount_serial_package(package_in, &header, &encrypted_data);
	
    buffer_t iv;
	iv.buffer = header.iv;
	iv.buffer_size = sizeof(header.iv);

	cipher->nc_off = 0;
	decrypt_data(&cipher->aes, &cipher->nc_off, &iv, &encrypted_data, &plain_data);

	int request_size = 512;
	buffer_t request = { .buffer = malloc(request_size), .buffer_size = request_size};

	path_t path = get_request_path_of_data_package(&plain_data);
	set_request_path_in_header(httpHeader, path);
    
	ret = mount_request( &request, httpHeader, data_package_to_json, &plain_data, credentials);

    free(plain_data.buffer);
    if(ret != CODE_SUCCESS) {
        printf("\n    ! Error: mount_request\n");
        free(request.buffer);
        return ret;
    }

	ret = send_data(request.buffer, request.buffer_size);	
    free(request.buffer);

	if(ret <  0)
		return 1;//TEE_ERROR_COMMUNICATION;

	#define HTTPS_RESPONSE_BUFFER_SIZE 1024
	buffer_t response = {.buffer = malloc(HTTPS_RESPONSE_BUFFER_SIZE), .buffer_size = HTTPS_RESPONSE_BUFFER_SIZE};

	int response_size = recv_data(response.buffer, response.buffer_size);
	if (response_size >= 0) {
		*response_code = get_response_code(&response);
		while (response_size > 0)
		{
			response_size = recv_data(response.buffer, response.buffer_size);
		}
	}

	if (!*response_code)
		return 1;//TEE_ERROR_CANCEL;
	return 0;
}

int create_serial_package(struct values_t * values , buffer_t * package_out, \
                struct cipher_handle_t * cipher)
{
    int res;
	serial_header_t header;
	buffer_t encrypted_data;
	buffer_t plain_data;

	uint32_t total_size = 0;

	if (values->data_code == 'S') {
		serie_t serie = { \
					.version = 17, \
					.unit = 2224179556, \
					.x = 0, \
					.y = 1, \
					.z = 2, \
					.dev = 0, \
					.r = 0, \
					.t0 = values->v0, \
					.t1 = values->v1 };

		res = create_data_package(SERIE, &plain_data, (void *) &serie);
	} else {
		record_t record = { \
					.version = 17, \
					.unit = 2224179556, \
					.value = values->v0, \
					.uncertainty = 0, \
					.x = 0, \
					.y = 1, \
					.z = 2, \
					.t = values->v1, \
					.dev = 0};
		
		res = create_data_package(RECORD, &plain_data, (void *) &record);	
	}

    if(res != CODE_SUCCESS) {
        return res;
    }

    unsigned char iv_char[16];
	buffer_t iv = { .buffer_size = 16, .buffer = iv_char};
	
    gerate_iv(cipher, &iv);
	memcpy(header.iv, iv.buffer, iv.buffer_size);

    cipher->nc_off = 0;
	encrypt_data(&cipher->aes, &cipher->nc_off, &iv, \
                &plain_data, &encrypted_data);
	
    free(plain_data.buffer);
    
	total_size = sizeof(header) + encrypted_data.buffer_size;
	
    if (package_out->buffer_size < total_size) {
		free(encrypted_data.buffer);
		return CODE_ERROR_SHORT_BUFFER;
	}

	header.encrypted_size = encrypted_data.buffer_size;

	mount_serial_package(package_out, &header, &encrypted_data);
	package_out->buffer_size = total_size;
    
	free(encrypted_data.buffer);
    
	return 0;
}

void gerate_values() {
	uint64_t  t = get_time_usec();
	t -= 600 * 1000000; // volta 10 min

	for (int i = 0; i < VALUES_LIST_SIZE; i++) {
		values_list[i].data_code = 'S';
		t += 60000000;// 1 min
		values_list[i].v0 = (uint64_t) 17;
		t += 60000000;// 1 min
		values_list[i].v1 = t; 
	}
}

void gerate_serial_datas(cipher_handle_t * cipher) {
	buffer_t buffer_aux;
	for (int i = 0; i < VALUES_LIST_SIZE; i++) {
		serial_list_index++;
		buffer_aux.buffer = serial_list[serial_list_index].data;
		buffer_aux.buffer_size = sizeof(serial_list[serial_list_index].data);
		
		create_serial_package(&values_list[i], &buffer_aux, cipher);
		serial_list[serial_list_index].len = buffer_aux.buffer_size;
	}
}

int main( int argc, char ** argv) 
{
	printf("\n test");
	printf("\n %d", sizeof(uint64_t));
    get_args(argc, argv, server_addr, &port);
	
    if (open_connections(server_addr, port, server_addr, lisha_ca_crt, lisha_ca_crt_len)) {
        printf("\n  ! Error: open_connections\n");
        exit(1);
    }

    //const char * hostname = HOSTNAME;
   struct HttpHeader_t httpHeader = { \
        .method = POST, \
        .path = API_GET, \
        .content_type = JSON, \
        .hostname = HOSTNAME, \
        .content_length = 0};
    
    struct credentials_t credentials = { \
		.domain = SECRET_DOMAIN, \
		.username = SECRET_USERNAME, \
		.password = SECRET_PASSWORD};
    
    struct cipher_handle_t cipher;

    initialize_crypto(&cipher, key, key_size);
	
	gerate_values();
	gerate_serial_datas(&cipher);

	uint64_t sum_time_interval = 0;
	int num_interval = 0;
    uint64_t timest0[SERIAL_LIST_SIZE];
	uint64_t timest1[SERIAL_LIST_SIZE];

	uint64_t timestamp_usec0;
	uint64_t timestamp_usec1; /* timestamp in microsecond */
		
	int response_code = 0;
	send_package( (buffer_t *) &(buffer_t){ .buffer = serial_list[0].data, .buffer_size = serial_list[0].len}, \
				&response_code, &cipher, &httpHeader, &credentials);
		
	for (int i = 1; i < SERIAL_LIST_SIZE; i++) {
		buffer_t package_data = { \
			.buffer = serial_list[i].data, \
			.buffer_size = serial_list[i].len
			};
		
		timestamp_usec0 = get_time_usec();
		// inicio envio
		send_package( &package_data, &response_code, &cipher, &httpHeader, &credentials);
		// fim envio
		timestamp_usec1 = get_time_usec();
		sum_time_interval += timestamp_usec1 - timestamp_usec0;
        timest0[i] = timestamp_usec0;
        timest1[i] = timestamp_usec1;
        num_interval++;
        
		/*
		if (i > 0) {
            sum_time_interval += timestamp_usec1 - timestamp_usec0;
            times[i] = timestamp_usec1 - timestamp_usec0;
            num_interval++;
            //diff = sum_time_interval*1.0/num_interval;
            //if (last_diff > 0 && last_diff < diff * 1.0001 && last_diff > diff * 0.9999) {
            //    break;
            //}
			*/
    }
	printf("\ntest");
	FILE * fp;
	
    fp = fopen ("/home/timestamps_send.txt","w");
	printf("\n fp: %d", (int) fp);
    
	fprintf(fp, "\nnum_interval,media(us)");
	fprintf(fp, "\n%d, %llu", num_interval, sum_time_interval/num_interval);
    fprintf(fp, "\nenvio, t0(us), t1(us)");
	
	for (int i = 1; i < VALUES_LIST_SIZE; ++i)
    {
        fprintf(fp, "\n%d, %llu, %llu", i, timest0[i], timest1[i]);
    }
	fclose (fp);
    
    close_conections();

    finish_crypto(&cipher);
    return 0;
}
