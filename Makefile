all: server client ca

server:
	g++ server.cc -o server -lcrypto -lssl

client:
	g++ client.cc -o client -lcrypto -lssl

ca:
	openssl genrsa -out private_key.pem 2048
	openssl req -new -x509 -key private_key.pem -out cert.pem -days 7

clean: 
	rm -f server client *.pem