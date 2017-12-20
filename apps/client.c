#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <malloc.h>
#include <string.h>
#include <sys/socket.h>
#include <resolv.h>
#include <netdb.h>
#include <wolfssl/ssl.h>
#include <wolfssl/openssl/err.h>
#include <wolfssl/openssl/x509.h>
#include <wolfssl/openssl/x509v3.h>
#include <wolfssl/openssl/ocsp.h>
#include <wolfssl/openssl/rand.h>
#include <wolfssl/wolfcrypt/settings.h>

#include <time.h>
#include <sys/time.h>

#define FAIL    -1

unsigned long get_current_microseconds()
{
    struct timeval curr;
    gettimeofday(&curr, NULL);

    return curr.tv_sec * 1000000 + curr.tv_usec;
}

int OpenConnection(const char *hostname, char *port)
{  
	int sd;
	struct addrinfo hints, *res;

	memset (&hints, 0, sizeof hints);

	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;

	getaddrinfo(hostname, port, &hints, &res);

	sd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
	if ( connect(sd, res->ai_addr, res->ai_addrlen) != 0 )
	{
		close(sd);
		perror(hostname);
		abort();
	} 
	return sd;
}

WOLFSSL_CTX* InitCTX(void)
{   
	WOLFSSL_METHOD *method;
	WOLFSSL_CTX *ctx;

	wolfSSL_add_all_algorithms();  /* Load cryptos, et.al. */
	wolfSSL_load_error_strings();   /* Bring in and register error messages */
	method = wolfTLSv1_2_client_method();  /* Create new client-method instance */
	ctx = wolfSSL_CTX_new(method);   /* Create new context */
	if ( ctx == NULL )
	{
		ERR_print_errors_fp(stderr);
		abort();
	}

	return ctx;
}

void ShowCerts(WOLFSSL* ssl)
{   X509 *cert;
	char *line;

	cert = wolfSSL_get_peer_certificate(ssl); /* get the server's certificate */
	if ( cert != NULL )
	{
		printf("Server certificates:\n");
		line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
		printf("Subject: %s\n", line);
		free(line);       /* free the malloc'ed string */
		line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
		printf("Issuer: %s\n", line);
		free(line);       /* free the malloc'ed string */

		X509_free(cert);     /* free the malloc'ed certificate copy */
	}
	else
		printf("No certificates.\n");
}

void LoadCertificates(WOLFSSL_CTX* ctx, char* CaCert, char* CertFile, char* KeyFile)
{
	int ret;

	/*verify the CertFile*/
	if ((ret = wolfSSL_CTX_load_verify_locations(ctx, CaCert, NULL)) != 1){
		printf("Client certificate verification failed!: %d\n", ret);
		abort();
	}
	/* set the local certificate from CertFile */
	if ((ret = wolfSSL_CTX_use_certificate_file(ctx, CertFile, SSL_FILETYPE_PEM)) <= 0 )
	{
		printf("Setting the CertFile failed!: %d\n", ret);
		abort();
	}
	/* set the private key from KeyFile (may be the same as CertFile) */
	if ((ret = wolfSSL_CTX_use_PrivateKey_file(ctx, KeyFile, SSL_FILETYPE_PEM)) <= 0 )
	{
		printf("Setting the private key failed!: %d\n", ret);
		abort();
	}
	/* verify private key */
	if ( !wolfSSL_CTX_check_private_key(ctx) )
	{
		printf("Private key does not match the public certificate\n");
		abort();
	}
}

int main(int count, char *strings[])
{   
	wolfSSL_Init();
	WOLFSSL_CTX *ctx;
	int server;
	WOLFSSL *ssl;
	char buf[1000*1000];
	int bytes;
	char *hostname, *portnum, *cert, *cacert, *key;

	if ( count != 6 )
	{
		printf("usage: %s <host_name> <port_num> <cert_file> <key_file> <ca cert>\n", strings[0]);
		exit(0);
	}
	wolfSSL_library_init();
	hostname=strings[1];
	portnum=strings[2];
	cert=strings[3];
	key=strings[4];
	cacert = strings[5];

	ctx = InitCTX();
	LoadCertificates(ctx, cacert, cert, key);
	server = OpenConnection(hostname, portnum);
	if (server <0)
		perror("Connect error\n");

	//Set this SSL_VERIFY_NONE if you want to neglect verifying server certificate
	//wolfSSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, 0);

	ssl = wolfSSL_new(ctx);      /* create new SSL connection state */
	//wolfSSL_CTX_set_cipher_list(ctx, "AES256-SHA256");
	wolfSSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_OFF);
	wolfSSL_set_fd(ssl, server);    /* attach the socket descriptor */

	int result, err;
	unsigned long start, end;
	start = get_current_microseconds();
	if ((result=wolfSSL_connect(ssl)) == FAIL ) {  /* perform the connection */
		err=wolfSSL_get_error(ssl, result);
		printf("wolfSSL_connect failed: %d\n", err);
	}
	else
	{
		end = get_current_microseconds();
		printf("wolfSSL_connect success: %ld\n", end - start);
	}

	close(server);         /* close socket */
	wolfSSL_CTX_free(ctx);        /* release context */

	return 0;
}
