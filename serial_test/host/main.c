#include <err.h>
#include <stdlib.h>

// tutorial
//https://blog.mbedded.ninja/programming/operating-systems/linux/linux-serial-ports-using-c-cpp/ 

// C library headers
#include <stdio.h>
#include <string.h>

// Linux headers
#include <fcntl.h> // Contains file controls like O_RDWR
#include <errno.h> // Error integer and strerror() function
#include <termios.h> // Contains POSIX terminal control definitions
#include <unistd.h> // write(), read(), close()

/* OP-TEE TEE client API (built by optee_client) */
#include <tee_client_api.h>

/* To the the UUID (found the the TA's h-file(s)) */
#include "../../aes_serial/ta/include/aes_serial_ta.h"

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
int config_serial_port(int * serial_port);

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

int config_serial_port(int * serial_port){

    struct termios tty;
    memset(&tty, 0, sizeof(tty));

    // Read in existing settings, and handle any error
    if(tcgetattr(*serial_port, &tty) != 0) {
        printf("Error %i from tcgetattr: %s\n", errno, strerror(errno));
        return 1;
    }

    /**
     * Control Modes (c_cflags)
     **/
    tty.c_cflag &= ~PARENB; // Clear parity bit, disabling parity
    tty.c_cflag &= ~CSTOPB; // Clear stop field, only one stop bit used in communication
    tty.c_cflag |= CS8; //bits per byte; CS5:5; CS6:6; CS7:7; CS8:8;
    tty.c_cflag &= ~CRTSCTS; // Disable RTS/CTS hardware flow control
    tty.c_cflag |= CREAD | CLOCAL; // Turn on READ & ignore ctrl lines (CLOCAL = 1)

    /**
     * Local Modes (c_lflag)
     **/
    tty.c_lflag &= ~ICANON; // Disable canonical mode
	// desabilitados por precaução
    // evita receber caracteres repetidos por causa do modo nao canonico
    tty.c_lflag &= ~ECHO; // Disable echo
    tty.c_lflag &= ~ECHOE; // Disable erasure
    tty.c_lflag &= ~ECHONL; // Disable new-line echo

    tty.c_lflag &= ~ISIG; // Disable interpretation of INTR, QUIT and SUSP

    /**
     * Input Modes (c_iflag)
     **/
    tty.c_iflag &= ~(IXON | IXOFF | IXANY); // Turn off s/w flow ctrl
    tty.c_iflag &= ~(IGNBRK|BRKINT|PARMRK|ISTRIP|INLCR|IGNCR|ICRNL); // Disable any special handling of received bytes

    /**
     * Output Modes (c_oflag)
     **/
    tty.c_oflag &= ~OPOST; // Prevent special interpretation of output bytes (e.g. newline chars)
    tty.c_oflag &= ~ONLCR; // Prevent conversion of newline to carriage return/line feed
    tty.c_cc[VTIME] = 5;    // Wait for up to 0.5s (5 deciseconds), returning as soon as any data is received.
    tty.c_cc[VMIN] = 0;

    /**
     * Baud Rate
     **/
	cfsetispeed(&tty, B115200);
    cfsetospeed(&tty, B115200);

    // ------------
    // Save configuration - ttyUSB0 termios struct
    // Save tty settings, also checking for error
    if(tcsetattr(*serial_port, TCSANOW, &tty) != 0) {
        printf("Error %i from tcsetattr: %s\n", errno, strerror(errno));
        return errno;
    }

    return 0;
}