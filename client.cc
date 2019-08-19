#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

int create_socket(int port)
{
    sockaddr_in addr;

    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(atoi("0.0.0.0"));

    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0)
    {
        printf("Fail to create socket");
        exit(-1);
    }
    if (connect(sockfd, (sockaddr *)&addr, sizeof(addr)) < 0)
    {
        printf("Fail to connect server");
        exit(-1);
    }
    return sockfd;
}

void init_openssl()
{
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
}

void cleanup_openssl()
{
    EVP_cleanup();
}

SSL_CTX *create_ssl_ctx()
{
    const SSL_METHOD *method = TLS_client_method();
    SSL_CTX *ctx = SSL_CTX_new(method);
    if (!ctx)
    {
        printf("Fail to create SSL context");
        exit(-1);
    }
    return ctx;
}

void configure_context(SSL_CTX *ctx)
{
    SSL_CTX_set_ecdh_auto(ctx, 1);
    if (SSL_CTX_use_certificate_file(ctx, "cert.pem", SSL_FILETYPE_PEM) <= 0)
    {
        ERR_print_errors_fp(stderr);
        exit(-1);
    }
    if (SSL_CTX_use_PrivateKey_file(ctx, "private_key.pem", SSL_FILETYPE_PEM) <= 0)
    {
        ERR_print_errors_fp(stderr);
        exit(-1);
    }
}

int main()
{
    init_openssl();
    SSL_CTX *ctx = create_ssl_ctx();
    configure_context(ctx);

    int fd = create_socket(4433);
    SSL *ssl = SSL_new(ctx);
    SSL_set_fd(ssl, fd);
    if (SSL_connect(ssl) < 0)
        ERR_print_errors_fp(stderr);
        
    char buffer[100];
    bzero(buffer, 100);
    SSL_read(ssl, buffer, 100);
    printf("Get message from server: %s", buffer);

    SSL_free(ssl);
    close(fd);
    SSL_CTX_free(ctx);
    cleanup_openssl();
    return 0;
}