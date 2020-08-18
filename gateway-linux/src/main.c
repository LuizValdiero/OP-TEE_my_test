#include <sys/time.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include <serial_keys.h>

#include <defines.h>
#include <serial_package.h>
#include <data_handler.h>
#include <crypto.h>
#include <utils/time_handler.h>
#include <connections_handler.h>

#define HOSTNAME "iot.lisha.ufsc.br"
#define PORT 443

#define LEN_BUFFER 2048

#define FILE_PATH_SIZE 1024
char file_path[FILE_PATH_SIZE];

#define SERIAL_LIST_SIZE 10
#define VALUES_LIST_SIZE 10

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

void get_args(int argc, char ** argv, char * file_path) {
    memset(file_path, 0, FILE_PATH_SIZE);
	if (argc == 2) {
        memset(file_path, 0, FILE_PATH_SIZE);
        strcpy(file_path, argv[1]);
        return;
    }
	strcpy(file_path, "NULL");    
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
	struct test_ctx ctx;
	get_args(argc, argv, file_path);
	
    if (open_connections(&ctx, HOSTNAME, sizeof(HOSTNAME), PORT)) {
        printf("\n  ! Error: open_connections\n");
        exit(1);
    }
    
    struct cipher_handle_t cipher;

    initialize_crypto(&cipher, key, key_size);
	
	gerate_values();
	gerate_serial_datas(&cipher);

	if(!memcmp(file_path, "NULL", 5)) {
		FILE * fp;
	
		printf("seve datas start");
	
		fp = fopen (file_path,"w");
		printf("\n fp: %d", (int) fp);
				
		fprintf(fp, "size,data");
		for (int i = 0; i < VALUES_LIST_SIZE; ++i)
		{
			fprintf(fp, "\n%d, %*.x", serial_list[i].len, serial_list[i].len+1, (unsigned int *) serial_list[i].data);
		}
		fclose (fp);		
		return 0;
	}

	uint64_t sum_time_interval = 0;
	int num_interval = 0;
    uint64_t timest0[SERIAL_LIST_SIZE];
	uint64_t timest1[SERIAL_LIST_SIZE];

	uint64_t timestamp_usec0;
	uint64_t timestamp_usec1; /* timestamp in microsecond */
		
	int response_code = 0;
	printf("send start");
	for (int i = 0; i < SERIAL_LIST_SIZE; i++) {
		buffer_t package_data = { \
			.buffer = serial_list[i].data, \
			.buffer_size = serial_list[i].len
			};
		
		timestamp_usec0 = get_time_usec();
		// inicio envio
		send_data(&ctx, &package_data, &response_code);
		// fim envio
		timestamp_usec1 = get_time_usec();
		sum_time_interval += timestamp_usec1 - timestamp_usec0;
        timest0[i] = timestamp_usec0;
        timest1[i] = timestamp_usec1;
        num_interval++;
    }
	printf("send finish");
	printf("\ntest");
	FILE * fp;
	
    fp = fopen ("/home/timestamps_gateway-linux_send.txt","w");
	printf("\n fp: %d", (int) fp);
    
	fprintf(fp, "\nnum_interval,media(us)");
	fprintf(fp, "\n%d, %llu", num_interval, sum_time_interval/num_interval);
    fprintf(fp, "\nenvio, t0(us), t1(us)");
	
	for (int i = 0; i < VALUES_LIST_SIZE; ++i)
    {
        fprintf(fp, "\n%d, %llu, %llu", i, timest0[i], timest1[i]);
    }
	fclose (fp);
    
    close_conections(&ctx);

    finish_crypto(&cipher);
    return 0;
}
