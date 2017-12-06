CC=gcc
LD=gcc
CFLAGS=-I/usr/local/include -Wcpp
LDFLAGS=-L/usr/local/lib -lwolfssl -lm -lz
SERV=server
CLNT=client
BIN=$(SERV) $(CLNT)
OBJ=server.o client.o

SERV_NAME=127.0.0.1
SERV_PORT=9999

CA_CERT=ca.pem
SERV_CERT=serv_cert.crt
SERV_PRIV=serv_priv.key
CLNT_CERT=clnt_cert.crt
CLNT_PRIV=clnt_priv.key

all: server client

server: server.o
	$(LD) -o server server.o $(LDFLAGS)

client: client.o
	$(LD) -o client client.o $(LDFLAGS)

server.o: server.c
	$(CC) -c $<

client.o: client.c
	$(CC) -c $<

server_test: server
	echo "server run source for test"	
	./$(SERV) $(SERV_PORT) $(SERV_CERT) $(SERV_PRIV) $(CA_CERT)

client_test: client
	echo "client run source for test"	
	./$(CLNT) $(SERV_NAME) $(SERV_PORT) $(CLNT_CERT) $(CLNT_PRIV) $(CA_CERT)

clean:
	$(RM) $(BIN) $(OBJ)
