#include <tls_handler.h>

#include <string.h>

int f_rng(void *rng __unused, unsigned char *output, size_t output_len)
{
	TEE_GenerateRandom(output, output_len);
	return 0;
}

void initialize_tls_structures(mbedtls_ssl_context* ssl, \
                mbedtls_ssl_session* ssl_sess, \
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
    mbedtls_ssl_session_init(ssl_sess);
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

int initialize_ctr_drbg(mbedtls_entropy_context * entropy, \
	mbedtls_ctr_drbg_context * ctr_drbg, const char * pers)
{
	int ret;
	DMSG( "\n  . Seeding the random number generator..." );

    if( ( ret = mbedtls_ctr_drbg_seed( ctr_drbg, f_rng, entropy,
                               (const unsigned char *) pers,
                               strlen(pers) ) ) != 0 )
    {
	    EMSG(" failed\n  ! mbedtls_ctr_drbg_seed returned %x\n", ret );
		tls_print_error_code(ret);
    }

    DMSG( "\n  . inialized" );

	return ret;
}

int set_ca_root_certificate(mbedtls_x509_crt * cacert, \
                const unsigned char * ca_crt, \
                size_t ca_crt_len)
{
	DMSG( "  . Loading the CA root certificate ..." );    
	int ret;

    ret = mbedtls_x509_crt_parse( cacert, ca_crt, ca_crt_len);
    if( ret < 0 )
    {
        EMSG( " failed\n  !  mbedtls_x509_crt_parse returned -0x%x\n\n", -ret );
		tls_print_error_code(ret);
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
		tls_print_error_code(ret);
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
		tls_print_error_code(ret);
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
		tls_print_error_code(ret);
    }
    DMSG("Hostname: %s", ssl->hostname);
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
			tls_print_error_code(ret);
			return ret;
        } else {
			IMSG( " .");
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
        tls_print_x509_crt_verify_info(flags);
    	return 1;
    }
    return 0;
}

int tls_handler_write(mbedtls_ssl_context * ssl, unsigned char * buffer, size_t size) {
    int ret;
    while( ( ret = mbedtls_ssl_write( ssl, buffer, size ) ) <= 0 )
    {
        if( ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE )
        {
            EMSG( " failed\n  ! mbedtls_ssl_write returned -0x%x\n\n", -ret );
			tls_print_error_code(ret);
			return ret;
        }
    }
    return ret;
}

int tls_handler_read(mbedtls_ssl_context * ssl, unsigned char * buffer, size_t size_buffer) {
    int ret;
    memset( buffer, 0, size_buffer);    
    while (1)
    {
        ret = mbedtls_ssl_read( ssl, buffer, size_buffer-1 );

        if( ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE )
            continue;

        if( ret == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY ) {
			EMSG("Error ssl read: %d\n ret == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY", ret);
			break;
		}
		if( ret < 0) {
			EMSG( " failed\n  ! mbedtls_ssl_read returned -0x%x\n\n", -ret );
            tls_print_error_code(ret);
			break;
		}
        break;
    }
    return ret;
}


int tls_is_connected(mbedtls_ssl_context* ssl) {
    if (ssl->state == MBEDTLS_SSL_HANDSHAKE_OVER)
        return 1;
    return 0;
}

int tls_reconnect(mbedtls_ssl_context* ssl, mbedtls_ssl_session* ssl_sess) {
    mbedtls_ssl_set_session(ssl, ssl_sess);
    handshake(ssl);
    mbedtls_ssl_get_verify_result(ssl);
    return 0;
}

void tls_print_error_code( int error_code) {
    char error_buf[100];
    mbedtls_strerror( error_code, error_buf, 100 );
	EMSG("\n  ! Last error was:-0x%x - %s\n\n", -error_code, error_buf );        
}

void tls_print_x509_crt_verify_info (int flags) {
    char vrfy_buf[512];
    mbedtls_x509_crt_verify_info( vrfy_buf, sizeof( vrfy_buf ), "  ! ", flags );
    EMSG( "%s\n", vrfy_buf );
}