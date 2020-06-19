#ifndef _TLS_HANDLER_H
#define _TLS_HANDLER_H

#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>

#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/ssl.h>
#include <mbedtls/x509.h>
#include <mbedtls/debug.h>
#include <mbedtls/certs.h>

//static int f_rng(void *rng __unused, \ 
//                unsigned char *output, \ 
//                size_t output_len);

int f_rng(void *rng __unused, \
                unsigned char *output, \
                size_t output_len);

void initialize_tls_structures(mbedtls_ssl_context* ssl, \
                mbedtls_ssl_config* conf, \
                mbedtls_entropy_context* entropy, \
                mbedtls_ctr_drbg_context* ctr_drbg, \
                mbedtls_x509_crt* cacert);

void finish_tls_structures(mbedtls_ssl_context* ssl, \
                mbedtls_ssl_config* conf, \
                mbedtls_entropy_context* entropy, \
                mbedtls_ctr_drbg_context* ctr_drbg, \
                mbedtls_x509_crt* cacert);

int initialize_ctr_drbg(mbedtls_entropy_context * entropy, \
            	mbedtls_ctr_drbg_context * ctr_drbg,
	            const char * pers);


int set_ca_root_certificate(mbedtls_x509_crt * cacert, \
                const unsigned char * api_ca_crt, \
                size_t api_ca_crt_len);

int setting_up_tls(mbedtls_ssl_config* conf, \
                mbedtls_ctr_drbg_context* ctr_drbg, \
                mbedtls_x509_crt* cacert);

int assign_configuration(mbedtls_ssl_context * ssl, mbedtls_ssl_config * conf);

int set_hostname(mbedtls_ssl_context * ssl ,const char * hostname);

void set_bio(mbedtls_ssl_context * ssl, void  * sess_socket, \
                        mbedtls_ssl_send_t *f_send, mbedtls_ssl_recv_t *f_recv, \
                        mbedtls_ssl_recv_timeout_t *f_recv_timeout);

int handshake(mbedtls_ssl_context * ssl);

int verify_server_certificate(mbedtls_ssl_context * ssl);

#endif // _TLS_HANDLER_H