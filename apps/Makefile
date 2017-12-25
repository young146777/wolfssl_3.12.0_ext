CC=gcc
LD=gcc
CFLAGS=-I/home/hwlee/wolfssl-comp-lib/include -Wcpp
LDFLAGS=-L/home/hwlee/wolfssl-comp-lib/lib -lwolfssl -L/home/hwlee/wolfssl-comp-lib/lib -lbrotlienc -lbrotlidec -lm -lz
ORIG_CFLAGS=-I/usr/local/include -Wcpp
ORIG_LDFLAGS=-L/usr/local/lib -lwolfssl -lm -lz 

SERV=server
CLNT=client
BIN=$(SERV) $(CLNT)
OBJ=server.o client.o

SERV_NAME=164.107.119.65
SERV_PORT=443

CA_CERT=ca.pem
SERV_CERT=serv_cert.pem
SERV_PRIV=serv_priv.key
CLNT_CERT=clnt_cert.pem
CLNT_PRIV=clnt_priv.key

SERV_CERT_2048=server_2048.pem
SERV_PRIV_2048=server_2048.key

SERV_CERT_4096=server_4096.pem
SERV_PRIV_4096=server_4096.key

TEST_CERT=test_cert.pem
TEST_PRIV=test_priv.key

CA_ECC_CERT=ecc/ca.crt
SERV_ECC_CERT=ecc/ssl_server.crt
SERV_ECC_PRIV=ecc/ssl_server.key
CLNT_ECC_CERT=ecc/ssl_client.crt
CLNT_ECC_PRIV=ecc/ssl_client.key

all: server client

orig: server_orig client_orig

server: server.o
	$(LD) -o server server.o $(LDFLAGS)

client: client.o
	$(LD) -o client client.o $(LDFLAGS)

server_orig: server.o
	$(LD) -o server server.o $(ORIG_LDFLAGS)

client_orig: client.o
	$(LD) -o client client.o $(ORIG_LDFLAGS)

server.o: server.c
	$(CC) $(CFLAGS) -c $<

client.o: client.c
	$(CC) $(CFLAGS) -c $<

server_test: server
	echo "server run source for test"	
	./$(SERV) $(SERV_PORT) $(TEST_CERT) $(TEST_PRIV) $(CA_CERT)

server_2048: server
	echo "server run source for test"	
	./$(SERV) $(SERV_PORT) $(SERV_CERT_2048) $(SERV_PRIV_2048) $(CA_CERT)

server_4096: server
	echo "server run source for test"	
	./$(SERV) $(SERV_PORT) $(SERV_CERT_4096) $(SERV_PRIV_4096) $(CA_CERT)

server_ecc: server
	echo "server with ecc cert"
	./$(SERV) $(SERV_PORT) $(SERV_ECC_CERT) $(SERV_ECC_PRIV) $(CA_ECC_CERT)

client_test: client
	echo "client run source for test"	
	./$(CLNT) $(SERV_NAME) $(SERV_PORT) $(CLNT_CERT) $(CLNT_PRIV) $(CA_CERT)

client_ecc: client
	echo "client with ecc cert"
	./$(CLNT) $(SERV_NAME) $(SERV_PORT) $(CLNT_ECC_CERT) $(CLNT_ECC_PRIV) $(CA_ECC_CERT)

clean:
	$(RM) $(BIN) $(OBJ)
