# My Package






## tls_test


Para fazermos uma conexao ssl/tls com um servidor utilizamos a TA (Trusted Application) socket_test que chama a pseudo-ta socket para abrir uma conecao tcp/ip, e a biblioteca mbedtls.

No optee_os a biblioteca mbedtls já está incluida para as TAs, mas para utilizar ssl/tls é necessario abilita-lo, no arquivo optee_os/lib/limbedtls/include/mbedtls_config_uta.h, adicionando:
```
/* mbed TLS feature support */
#define MBEDTLS_KEY_EXCHANGE_PSK_ENABLED
#define MBEDTLS_SSL_PROTO_TLS1_2

// add a ciphersuite
#define MBEDTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED


#define MBEDTLS_SSL_CLI_C
#define MBEDTLS_SSL_SRV_C
#define MBEDTLS_SSL_TLS_C
```
Para mais informacoes de configuracoes consulte https://github.com/ARMmbed/mbedtls/blob/development/include/mbedtls/config.h

Em optee_os/lib/libmbedtls/sub.mk também adicionamos
```
SRCS_TLS += ssl_msg.c
```

### mbedTLS

https://tls.mbed.org/high-level-design

https://tls.mbed.org/api/index.html

Para a biblioteca mbedtls acessar nossa conexao tcp/ip implemetamos as funcoes f_send e f_recv.

```
void mbedtls_ssl_set_bio	(	
        mbedtls_ssl_context * 	ssl,
        void * 	p_bio,
        mbedtls_ssl_send_t * 	f_send,
        mbedtls_ssl_recv_t * 	f_recv,
        mbedtls_ssl_recv_timeout_t * 	f_recv_timeout
    )
```
#### recv

```
int mbedtls_net_recv( void *ctx, unsigned char *buf, size_t len );
```

#### recv timeout

```
int mbedtls_net_recv_timeout( void *ctx, unsigned char *buf,
                              size_t len, uint32_t timeout );
```

#### send

```
int mbedtls_net_send( void *ctx, const unsigned char *buf, size_t len );

```

Para Criptografia
Para geracao de numeros pseudo-aleatorios definimos a funcao f_rng.

```
static int f_rng(void *rng __unused, unsigned char *output, size_t output_len)
{
	TEE_GenerateRandom(output, output_len);
	return 0;
}

```