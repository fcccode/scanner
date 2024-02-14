#include "tls.h"


//////////////////////////////////////////////////////////////////////////////////////////////////


//void configure_client_context(SSL_CTX * ctx)
//{
//    /*
//     * Configure the client to abort the handshake if certificate verification fails
//     */
//    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
//
//    /*
//     * In a real application you would probably just use the default system certificate trust store and call:
//     *     SSL_CTX_set_default_verify_paths(ctx);
//     * In this demo though we are using a self-signed certificate, so the client must trust it directly.
//     */
//    if (!SSL_CTX_load_verify_locations(ctx, "cert.pem", NULL)) {
//        ERR_print_errors_fp(stderr);
//        exit(EXIT_FAILURE);
//    }
//}


void SetClientOpt(SSL * ssl)
/*
功能：设置一些本地的选项，用于控制TLS通讯。
*/
{
    UNREFERENCED_PARAMETER(ssl);

}


void DumpServerInfo(SSL * ssl)
/*
获取并打印TLS通讯的对方（服务端）的信息。
*/
{
    printf("ServerInfo:\r\n\r\n\r\n");

    printf("cipher:%s.\r\n", SSL_get_cipher(ssl));//形如：ECDHE-RSA-AES128-GCM-SHA256。
    printf("cipher_version:%s.\r\n", SSL_get_cipher_version(ssl));//形如：TLSv1.2
    printf("cipher_name:%s.\r\n", SSL_get_cipher_name(ssl));//形如：ECDHE-RSA-AES128-GCM-SHA256 

    int alg_bits = 0;
    SSL_get_cipher_bits(ssl, &alg_bits);

    printf("ssl_version:%s.\r\n", SSL_get_version(ssl));//形如：TLSv1.2

    bool is_secure_renegotiation_support = SSL_get_secure_renegotiation_support(ssl);
    printf("is_secure_renegotiation_support:%s.\r\n", is_secure_renegotiation_support ? "yes" : "no");

    //const char * psk_identity_hint = SSL_get_psk_identity_hint(ssl);
    //const char * psk_identity = SSL_get_psk_identity(ssl);

    //char * srp_username = SSL_get_srp_username(ssl);
    //char * srp_userinfo = SSL_get_srp_userinfo(ssl);

    //int security_level = SSL_get_security_level(ssl);

    //unsigned char random[MAX_PATH] = {};
    //size_t random_len = SSL_get_server_random(ssl, random, sizeof(random));

    SSL_SESSION * ssl_session = SSL_get_session(ssl);

    //这个函数真的还得看看内部实现。
    //SSL_SESSION_print的简单的封装。
    //详见：openssl\ssl\ssl_txt.c
    //不过这个函数，还需自己实现下，因为SSL_SESSION对外是透明的。
    SSL_SESSION_print_fp(stdout, ssl_session);
    //SSL_SESSION_print(ssl_session);

    //SSL_SESSION_print_keylog_fp(stdout, ssl_session);
    //SSL_SESSION_print_keylog(ssl_session);

    X509 * Server_certificate = SSL_get_peer_certificate(ssl);
    //DumpX509(Server_certificate);
    X509_free(Server_certificate);

    printf("\r\n\r\n\r\n");
}


void my_SSL_CTX_keylog_cb_func(const SSL * ssl, const char * line)
/*
这个函数很重要，一般不会提供对外注册的。

这个函数发生在SSL_connect时机，SSL_write和SSL_read时没有发生。
此时line是有内容的，ssl也是有内容的，应该是有效的。

打印示例：
ssl:0000015CD62B58E0, line:CLIENT_RANDOM fddc5b53a0f95ed61b85f693e808a39a011724242f433332fed6f62e4ffc23c2 1f69643e56adac41eeb86948bd580d6048b7c7c9f58baddd833054798f6151f8b59e948933098ed0b6e4f112f6073154

https://www.openssl.org/docs/man1.1.1/man3/SSL_CTX_set_keylog_callback.html
*/
{
    printf("ssl:%p, line:%s\n\n\n", ssl, line);
}


int WINAPI tls_client(int argc, char ** argv)
/*
功能：获取HTTPS的服务端信息，如：证书等。

第二个参数是IPv4，第三个参数是端口。
后期改为支持IPv6.
*/
{
    if (argc != 3) {
        printf("Usage: ip port\n");
        return 1;
    }

    SSL * ssl = nullptr;
    SSL_CTX * ssl_ctx = nullptr;
    SOCKET client_socket = 0;

    __try {
        char * RemoteIPv4 = argv[1];/* If client get remote server address (could be 127.0.0.1) */
        u_short RemotePort = (u_short)atoi(argv[2]);

        WSADATA wsaData;
        int iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);// Initialize Winsock
        if (iResult != 0) {
            printf("WSAStartup failed with error: %d\n", iResult);
            __leave;
        }

        client_socket = socket(AF_INET, SOCK_STREAM, 0);/* Create "bare" socket */

        struct sockaddr_in addr;
        addr.sin_family = AF_INET;
        inet_pton(AF_INET, RemoteIPv4, &addr.sin_addr.s_addr);
        addr.sin_port = htons(RemotePort);
        if (connect(client_socket, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
            perror("Unable to TCP connect to server");
            __leave;
        }

        const SSL_METHOD * method = TLS_client_method();
        ssl_ctx = SSL_CTX_new(method);
        //configure_client_context(ssl_ctx);/* Configure client context so we verify the server correctly */

        SSL_CTX_set_keylog_callback(ssl_ctx, my_SSL_CTX_keylog_cb_func);

        /* Create client SSL structure using dedicated client socket */
        ssl = SSL_new(ssl_ctx);
        SSL_set_fd(ssl, (int)client_socket);

        SSL_set_tlsext_host_name(ssl, RemoteIPv4);/* Set host name for SNI */
        SSL_set1_host(ssl, RemoteIPv4);/* Configure server hostname check */

        SetClientOpt(ssl);

        if (SSL_connect(ssl) == 1) {/* Now do SSL connect with server */

            //DumpServerInfo(ssl);

            char * txbuf = (char *)"GET / HTTP/1.0\r\n\r\n";
            int txlen = (int)strlen(txbuf);
            if (SSL_write(ssl, txbuf, txlen) <= 0) {/* Send it to the server */
                printf("Server closed connection\n");
                ERR_print_errors_fp(stderr);
                __leave;
            }

            printf("服务端返回的信息：\r\n\r\n\r\n");

            for (;;) {
                char rxbuf[MAX_PATH] = {};
                size_t rxcap = sizeof(rxbuf) - sizeof(char);
                int rxlen = SSL_read(ssl, rxbuf, (int)rxcap);
                if (rxlen <= 0) {
                    //printf("Server closed connection\n");
                    ERR_print_errors_fp(stderr);
                    printf("\r\n\r\n\r\n");
                    __leave;
                } else {/* Show it */
                    rxbuf[rxlen] = 0;
                    printf("%s", rxbuf);
                }
            }
        } else {
            printf("SSL connection to server failed\n\n");
            ERR_print_errors_fp(stderr);
        }
    } __finally {
        if (ssl != NULL) {
            SSL_shutdown(ssl);
            SSL_free(ssl);
        }

        SSL_CTX_free(ssl_ctx);

        if (client_socket != -1)
            closesocket(client_socket);

        WSACleanup();
    }

    return 0;
}


//////////////////////////////////////////////////////////////////////////////////////////////////
