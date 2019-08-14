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
    addr.sin_addr.s_addr = htonl(INADDR_ANY);

    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0)
    {
        printf("Fail to create socket");
        exit(-1);
    }
    if (bind(sockfd, (sockaddr *)&addr, sizeof(addr)) < 0)
    {
        printf("Fail to bind");
        exit(-1);
    }
    if (listen(sockfd, 1) < 0)
    {
        printf("Unable to listen");
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
    const SSL_METHOD *method = TLS_server_method();
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
    if (SSL_CTX_use_certificate_file(ctx, "ca/cacert.pem", SSL_FILETYPE_PEM) <= 0)
    {
        ERR_print_errors_fp(stderr);
        exit(-1);
    }
    if (SSL_CTX_use_PrivateKey_file(ctx, "ca/privkey.pem", SSL_FILETYPE_PEM) <= 0)
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

    int serverfd = create_socket(4433);

    while (1)
    {
        sockaddr_in addr;
        uint len = sizeof(addr);

        int clientfd = accept(serverfd, (sockaddr *)&addr, (socklen_t *)&len);
        if (clientfd < 0)
        {
            printf("Fail to accecpt");
            exit(-1);
        }

        SSL *ssl = SSL_new(ctx);
        SSL_set_fd(ssl, clientfd);
        const char reply[] = "Hello SSL\n";
        if (SSL_accept(ssl) <= 0)
        {
            ERR_print_errors_fp(stderr);
        }
        else
        {
            SSL_write(ssl, reply, strlen(reply));
        }
        SSL_free(ssl);
        close(clientfd);
    }
    close(serverfd);
    SSL_CTX_free(ctx);
    cleanup_openssl();
}