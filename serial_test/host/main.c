#include <err.h>
#include <stdlib.h>

// C library headers
#include <stdio.h>
#include <string.h>

/* OP-TEE TEE client API (built by optee_client) */
#include <tee_client_api.h>

/* To the the UUID (found the the TA's h-file(s)) */
#include "../../aes_serial/ta/include/aes_serial_ta.h"
#include "ca_serial_handler.h"

#define MAX_BUFFER_SIZE 256

/* TEE resources */
struct test_ctx {
	TEEC_Context ctx;
	TEEC_Session sess;
};

void prepare_tee_context(struct test_ctx *ctx)
{
	TEEC_Result res;

	/* Initialize a context connecting us to the TEE */
	res = TEEC_InitializeContext(NULL, &ctx->ctx);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InitializeContext failed with code 0x%x", res);

}


void prepare_tee_session(struct test_ctx *ctx, TEEC_UUID * uuid)
{
	uint32_t origin;
	TEEC_Result res;

	/* Open a session with the TA */
	res = TEEC_OpenSession(&ctx->ctx, &ctx->sess, uuid,
			       TEEC_LOGIN_PUBLIC, NULL, NULL, &origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_Opensession failed with code 0x%x origin 0x%x",
			res, origin);
}

static void get_args(int argc, char *argv[], char **dev);

int main(int argc, char *argv[])
{
	struct test_ctx ctx;
	TEEC_Result res;
	uint32_t origin;
	TEEC_Operation op;
    TEEC_UUID uuid_ta_aes_serial = TA_AES_SERIAL_UUID;
    char * dev; //ttyUSB0
    char read_buf [MAX_BUFFER_SIZE];
    char invert_buf [MAX_BUFFER_SIZE];
    size_t num_bytes;

    memset(invert_buf, 0x00, MAX_BUFFER_SIZE);

	get_args(argc, argv, &dev);
	
    // file descriptor - /dev/ttyUSB0
    int serial_port = open(dev, O_RDWR);
    
    // Check for errors
    if(serial_port < 0) {
        printf("Error %i from open: %s\n", errno, strerror(errno));
        return errno;
    }

    printf("Open: %s\n", dev);

    if (config_serial_port(&serial_port)) {
        printf("Error - Serial port config");
        return errno;
    }

    memset(&read_buf, '\0', sizeof(read_buf));

    num_bytes = strlen("aabb");
    memcpy( read_buf, "aabb", num_bytes);
    printf("write %s\n", read_buf);
    num_bytes = write(serial_port, read_buf, num_bytes);
    printf("writed %d bytes\n", num_bytes);
    memset(read_buf,0x00, MAX_BUFFER_SIZE);

    prepare_tee_context(&ctx);

	while (1)
    {

        num_bytes = write(serial_port, read_buf, num_bytes);
        printf("writed %d bytes\n", num_bytes);
        memset(read_buf,0x00, MAX_BUFFER_SIZE);
        memset(invert_buf,0x00, MAX_BUFFER_SIZE);
        num_bytes = read(serial_port, &read_buf, MAX_BUFFER_SIZE);
        
        if (!num_bytes)
            continue;   

        if (num_bytes < 0) {
            printf("Error reading: %s", strerror(errno));
            continue;
        }
        printf("Read %i bytes. Received message: < %s >\n", num_bytes, read_buf);
        fflush(stdout);
        close(serial_port);

        printf("prepare tee session ok\n");
        fflush(stdout);

        prepare_tee_session(&ctx, &uuid_ta_aes_serial);
        
        printf("prepare tee session - AES_SERIAL - ok\n");

        memset(&op, 0, sizeof(op));
        op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
                        TEEC_MEMREF_TEMP_OUTPUT,
                        TEEC_NONE, TEEC_NONE);
        
        op.params[0].tmpref.buffer = read_buf;
        op.params[0].tmpref.size = num_bytes;
        memset(invert_buf, 0x00, num_bytes);
        op.params[1].tmpref.buffer = invert_buf;
        op.params[1].tmpref.size = num_bytes;
        printf("set params ok\n");


        printf("buffer: ");

        //uint32_t n = 0;
        for (uint32_t n = 0; n < op.params[0].tmpref.size; n++)
            printf("%02x ", ((uint8_t *)op.params[0].tmpref.buffer)[n]);
        printf("\n");

        res = TEEC_InvokeCommand(&ctx.sess, TA_ENCRYPT, &op, &origin);
        
        if (res != TEEC_SUCCESS)
            errx(1, "TEEC_InvokeCommand(CIPHER) failed 0x%x origin 0x%x",
                res, origin);

        printf("Encrypted buffer: ");
        for (uint32_t n = 0; n < op.params[1].tmpref.size; n++)
            printf("%02x ", ((uint8_t *)op.params[1].tmpref.buffer)[n]);
        printf("\n");

        printf("ENCRYPT message (%i): < %s >\n", op.params[1].tmpref.size, (char *) op.params[1].tmpref.buffer );

        num_bytes = write(serial_port, invert_buf, num_bytes);

        TEEC_CloseSession(&ctx.sess);

        printf("Inverted message (%i): < %s >\n", num_bytes, invert_buf );
        memcpy(read_buf, invert_buf, num_bytes);

    };

    TEEC_FinalizeContext(&ctx.ctx);

	return 0;
}

static void get_args(int argc, char *argv[], char **dev)
{
	if (argc != 2) {
		warnx("Unexpected number of arguments %d (expected 1) \n %s <device>",
		      argc - 1, argv[0]);
		exit(1);
	}
	*dev = argv[1];    
}
