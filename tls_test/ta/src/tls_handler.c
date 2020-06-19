#include "tls_handler.h"

#include <string.h>

int f_rng(void *rng __unused, unsigned char *output, size_t output_len)
{
	TEE_GenerateRandom(output, output_len);
	return 0;
}

void initialize_tls_structures(mbedtls_ssl_context* ssl, \
                mbedtls_ssl_config* conf, \
                mbedtls_entropy_context* entropy, \
                mbedtls_ctr_drbg_context* ctr_drbg, \
                mbedtls_x509_crt* cacert)
{
    mbedtls_ctr_drbg_init( ctr_drbg);
	mbedtls_entropy_init( entropy);
    mbedtls_x509_crt_init( cacert);
    mbedtls_ssl_init( ssl);
    mbedtls_ssl_config_init( conf);
}

void finish_tls_structures(mbedtls_ssl_context* ssl, \
                mbedtls_ssl_config* conf, \
                mbedtls_entropy_context* entropy, \
                mbedtls_ctr_drbg_context* ctr_drbg, \
                mbedtls_x509_crt* cacert)
{
	mbedtls_x509_crt_free( cacert );
    mbedtls_ssl_free( ssl );
    mbedtls_ssl_config_free( conf );
    mbedtls_ctr_drbg_free( ctr_drbg );
    mbedtls_entropy_free( entropy );
}

int initialize_ctr_drbg(mbedtls_entropy_context * entropy,
	mbedtls_ctr_drbg_context * ctr_drbg,
	const char * pers)
{
	int ret;
	DMSG( "\n  . Seeding the random number generator..." );

    if( ( ret = mbedtls_ctr_drbg_seed( ctr_drbg, f_rng, entropy,
                               (const unsigned char *) pers,
                               strlen(pers) ) ) != 0 )
    {
	    EMSG(" failed\n  ! mbedtls_ctr_drbg_seed returned %x\n", ret );
		//char error_buf[100];
		//mbedtls_strerror( ret, error_buf, 100 );
		//DMSG("\n  ! Last error was:-0x%x - %s\n\n", -ret, error_buf );
    }

DMSG( "\n  . inialized" );

	return ret;
}

int set_ca_root_certificate(mbedtls_x509_crt * cacert, \
                const unsigned char * api_ca_crt, \
                size_t api_ca_crt_len)
{
	DMSG( "  . Loading the CA root certificate ..." );    
	int ret;

    ret = mbedtls_x509_crt_parse( cacert, api_ca_crt, api_ca_crt_len);
    if( ret < 0 )
    {
        EMSG( " failed\n  !  mbedtls_x509_crt_parse returned -0x%x\n\n", -ret );
		//char error_buf[100];
		//mbedtls_strerror( ret, error_buf, 100 );
		//DMSG("\n  ! Last error was:-0x%x - %s\n\n", -ret, error_buf );
    } else {
        DMSG( " \n  .  mbedtls_x509_crt_parse returned 0x%x\n\n", ret );
	}

	return 0;
}

int setting_up_tls(mbedtls_ssl_config* conf, \
                mbedtls_ctr_drbg_context* ctr_drbg, \
                mbedtls_x509_crt* cacert)
{
	int ret;

	DMSG( "\n  . Setting up the SSL/TLS structure..." );

	DMSG( "\n  . mbedtls_ssl_config_defaults");	
    if( ( ret = mbedtls_ssl_config_defaults(conf,
                    MBEDTLS_SSL_IS_CLIENT,
                    MBEDTLS_SSL_TRANSPORT_STREAM,
                    MBEDTLS_SSL_PRESET_DEFAULT ) ) != 0 )
    {
        EMSG( " failed\n  ! mbedtls_ssl_config_defaults returned %d\n\n", ret );
		//char error_buf[100];
		//mbedtls_strerror( ret, error_buf, 100 );
		//EMSG("\n  ! Last error was:-0x%x - %s\n\n", -ret, error_buf );
    }

/* OPTIONAL is not optimal for security,
     * but makes interop easier in this simplified example */
    DMSG( "\n  . mbedtls_ssl_conf_authmode");
	mbedtls_ssl_conf_authmode( conf, MBEDTLS_SSL_VERIFY_OPTIONAL );
    DMSG( "\n  . mbedtls_ssl_conf_rng");
	mbedtls_ssl_conf_rng( conf, f_rng, ctr_drbg );
    DMSG( "\n  . mbedtls_ssl_conf_chain");	
	mbedtls_ssl_conf_ca_chain( conf, cacert, NULL );
	return 0;
}

int assign_configuration(mbedtls_ssl_context * ssl, mbedtls_ssl_config * conf)
{
    int ret;
    DMSG( "\n  . mbedtls_ssl_setup");	
    if( ( ret = mbedtls_ssl_setup( ssl, conf ) ) != 0 )
    {
        EMSG( " failed\n  ! mbedtls_ssl_setup returned %d  -0x%x\n\n", ret, -ret );
		//char error_buf[100];
		//mbedtls_strerror( ret, error_buf, 100 );
		//EMSG("\n  ! Last error was:-0x%x - %s\n\n", -ret, error_buf );
    }
    return ret;
}

int set_hostname(mbedtls_ssl_context * ssl ,const char * hostname)
{
	int ret;
    DMSG( "\n  . mbedtls_ssl_set_hostname");	
    if( ( ret = mbedtls_ssl_set_hostname( ssl, hostname ) ) != 0 )
    {
        EMSG( " failed\n  ! mbedtls_ssl_set_hostname returned %d\n\n", ret );
		//char error_buf[100];
		//mbedtls_strerror( ret, error_buf, 100 );
		//EMSG("\n  ! Last error was:-0x%x - %s\n\n", -ret, error_buf );
    }
    return ret;
}

void set_bio(mbedtls_ssl_context * ssl, void  * sess_socket, \
                        mbedtls_ssl_send_t *f_send, mbedtls_ssl_recv_t *f_recv, \
                        mbedtls_ssl_recv_timeout_t *f_recv_timeout)
{
    DMSG( "\n  . mbedtls_ssl_set_bio");	
	mbedtls_ssl_set_bio( ssl, sess_socket, f_send, f_recv, f_recv_timeout);
}


int handshake(mbedtls_ssl_context * ssl)
{
	int ret;

	DMSG( "\n  . Performing the SSL/TLS handshake..." );
    
    while( ( ret = mbedtls_ssl_handshake( ssl ) ) != 0 )
    {
        if( ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE )
        {
            EMSG( " failed\n  ! mbedtls_ssl_handshake returned -0x%x\n\n", -ret );
			//char error_buf[100];
        	//mbedtls_strerror( ret, error_buf, 100 );
			//EMSG("\n  ! Last error was:-0x%x - %s\n\n", -ret, error_buf );
            return ret;
        } else {
			DMSG( " .");
		}
    }

	return 0;
}

int verify_server_certificate(mbedtls_ssl_context * ssl)
{
	uint32_t flags;
	
	DMSG( "  . Verifying peer X.509 certificate..." );
    if( ( flags = mbedtls_ssl_get_verify_result( ssl ) ) != 0 )
    {
        EMSG( " failed\n" );
        //char vrfy_buf[512];
        //mbedtls_x509_crt_verify_info( vrfy_buf, sizeof( vrfy_buf ), "  ! ", flags );
        //DMSG( "%s\n", vrfy_buf );
    }

	return TEE_SUCCESS;
}