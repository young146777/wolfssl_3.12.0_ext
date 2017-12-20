#include <errno.h>
#include <unistd.h>
#include <malloc.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <resolv.h>
#include <wolfssl/ssl.h>
#include <wolfssl/openssl/rand.h>
#include <wolfssl/openssl/err.h>
#include <wolfssl/options.h>
#include <math.h>
#include <stdlib.h>
#include <signal.h>

#define FAIL    -1

int server;

static INLINE void SetDH(WOLFSSL* ssl) 
{
	/* dh1024 p */
	static unsigned char p[] =
	{    
		0xE6, 0x96, 0x9D, 0x3D, 0x49, 0x5B, 0xE3, 0x2C, 0x7C, 0xF1, 0x80, 0xC3,
		0xBD, 0xD4, 0x79, 0x8E, 0x91, 0xB7, 0x81, 0x82, 0x51, 0xBB, 0x05, 0x5E,
		0x2A, 0x20, 0x64, 0x90, 0x4A, 0x79, 0xA7, 0x70, 0xFA, 0x15, 0xA2, 0x59,
		0xCB, 0xD5, 0x23, 0xA6, 0xA6, 0xEF, 0x09, 0xC4, 0x30, 0x48, 0xD5, 0xA2,
		0x2F, 0x97, 0x1F, 0x3C, 0x20, 0x12, 0x9B, 0x48, 0x00, 0x0E, 0x6E, 0xDD,
		0x06, 0x1C, 0xBC, 0x05, 0x3E, 0x37, 0x1D, 0x79, 0x4E, 0x53, 0x27, 0xDF,
		0x61, 0x1E, 0xBB, 0xBE, 0x1B, 0xAC, 0x9B, 0x5C, 0x60, 0x44, 0xCF, 0x02,
		0x3D, 0x76, 0xE0, 0x5E, 0xEA, 0x9B, 0xAD, 0x99, 0x1B, 0x13, 0xA6, 0x3C,
		0x97, 0x4E, 0x9E, 0xF1, 0x83, 0x9E, 0xB5, 0xDB, 0x12, 0x51, 0x36, 0xF7,
		0x26, 0x2E, 0x56, 0xA8, 0x87, 0x15, 0x38, 0xDF, 0xD8, 0x23, 0xC6, 0x50,
		0x50, 0x85, 0xE2, 0x1F, 0x0D, 0xD5, 0xC8, 0x6B,
	};   

	/* dh1024 g */
	static unsigned char g[] =
	{    
		0x02,
	};   

	wolfSSL_SetTmpDH(ssl, p, sizeof(p), g, sizeof(g));
}


int OpenListener(int port)
{   int sd;
	struct sockaddr_in addr;

	sd = socket(PF_INET, SOCK_STREAM, 0);
	bzero(&addr, sizeof(addr));
	int option = 1;
	setsockopt(sd, SOL_SOCKET, SO_REUSEADDR, &option, sizeof(option));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	addr.sin_addr.s_addr = INADDR_ANY;

	if ( bind(sd, (struct sockaddr*)&addr, sizeof(addr)) != 0 )
	{
		perror("can't bind port");
		abort();
	}
	if ( listen(sd, 10) != 0 )
	{
		perror("Can't configure listening port");
		abort();
	}
	return sd;
}


WOLFSSL_CTX* InitServerCTX(void)
{   
	WOLFSSL_METHOD *method;
	WOLFSSL_CTX *ctx;

	wolfSSL_add_all_algorithms();  /* load & register all cryptos, etc. */
	wolfSSL_load_error_strings();   /* load all error messages */
	method = wolfTLSv1_2_server_method();  /* create new server-method instance */
	ctx = wolfSSL_CTX_new(method);   /* create new context from method */
	
	if ( ctx == NULL )
	{
		ERR_print_errors_fp(stderr);
		abort();
	}
	
	return ctx;
}

void LoadCertificates(WOLFSSL_CTX* ctx, char* CertFile, char* KeyFile, char* CaFile)
{
	int ret;
	char *caCertFile = CaFile;

	/*verify the CertFile*/
	if ((ret = wolfSSL_CTX_load_verify_locations(ctx, caCertFile, NULL)) != 1){
		printf("Server certificate verification failed!: %d\n", ret);
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

	/*force the client-side have a certificate*/
//	wolfSSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
}

void ShowCerts(WOLFSSL* ssl)
{   X509 *cert;
	char *line;

	cert = wolfSSL_get_peer_certificate(ssl); /* Get certificates (if available) */
	if ( cert != NULL )
	{
		printf("Peer certificates:\n");
		line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
		printf("Subject: %s\n", line);
		free(line);
		line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
		printf("Issuer: %s\n", line);
		free(line);
		X509_free(cert);
	}
	else
		printf("No certificates.\n");
}

int main(int count, char *strings[])
{  
	wolfSSL_Init();
	WOLFSSL_CTX *ctx;
	char *portnum, *cert, *key, *ca;

	if ( count != 5 )
	{
		printf("Usage: %s <portnum> <cert_file> <key_file> <ca_cert>\n", strings[0]);
		exit(1);
	}
	wolfSSL_library_init();

	portnum = strings[1];
	cert = strings[2];
	key = strings[3];
	ca = strings[4];

	ctx = InitServerCTX();        /* initialize SSL */
	LoadCertificates(ctx, cert, key, ca);
	server = OpenListener(atoi(portnum));    /* create server socket */

	struct sockaddr_in addr;
	char str[INET_ADDRSTRLEN];
	socklen_t len = sizeof(addr);
	WOLFSSL *ssl;

	while(1)
	{
		int client = accept(server, (struct sockaddr*)&addr, &len);  /* accept connection as usual */
		inet_ntop(AF_INET, &(addr.sin_addr), str, INET_ADDRSTRLEN);
		printf("Connecting from: %s\nPort: %d\n",str, ntohs(addr.sin_port));
		ssl = wolfSSL_new(ctx);              /* get new SSL state with context */
		wolfSSL_set_fd(ssl, client);      /* set connection socket to SSL state */
		SetDH(ssl);

		int result, err;
		if ( (result=wolfSSL_accept(ssl)) == FAIL ) {    /* do SSL-protocol accept */
			err=wolfSSL_get_error(ssl, result);
			printf("wolfSSL_accept failed with errno: %d\n", err);
		}
		else
			printf("wolfSSL_accept success\n");

		close(client);
	}

	int client = accept(server, (struct sockaddr*)&addr, &len);  /* accept connection as usual */
	inet_ntop(AF_INET, &(addr.sin_addr), str, INET_ADDRSTRLEN);
	printf("Connecting from: %s\nPort: %d\n",str, ntohs(addr.sin_port));
	ssl = wolfSSL_new(ctx);              /* get new SSL state with context */
	wolfSSL_CTX_set_cipher_list(ctx, "AES256-SHA256");
	wolfSSL_set_fd(ssl, client);      /* set connection socket to SSL state */
	wolfSSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_OFF);

	int result, err;
	if ( (result=wolfSSL_accept(ssl)) == FAIL ) {    /* do SSL-protocol accept */
		err=wolfSSL_get_error(ssl, result);
		printf("wolfSSL_accept failed with errno: %d\n", err);
	}
  	printf("Success\n");
	SSL_free(ssl);
	SSL_CTX_free(ctx);         /* release context */
	close(server);          /* close server socket */

	return 0;
}
