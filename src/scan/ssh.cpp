#include "ssh.h"


static const char * pubkey = "/home/username/.ssh/id_rsa.pub";
static const char * privkey = "/home/username/.ssh/id_rsa";
static const char * username = "username";
static const char * password = "password";
static const char * sftppath = "/tmp/sftp_mkdir";


int IsSsh(int argc, char * argv[])
/*
命令行参数：192.168.31.133 root correy /tmp/sftp_mkdir

测试成功。
没有配置文件，可以使用默认的用户名和密码。
*/
{
    uint32_t hostaddr;
    libssh2_socket_t sock;
    int i, auth_pw = 1;
    struct sockaddr_in sin;
    const char * fingerprint;
    int rc;
    LIBSSH2_SESSION * session = NULL;
    LIBSSH2_SFTP * sftp_session;

#ifdef WIN32
    WSADATA wsadata;
    rc = WSAStartup(MAKEWORD(2, 0), &wsadata);
    if (rc) {
        fprintf(stderr, "WSAStartup failed with error: %d\n", rc);
        return 1;
    }
#endif

    if (argc > 1) {
        hostaddr = inet_addr(argv[1]);
    } else {
        hostaddr = htonl(0x7F000001);
    }
    if (argc > 2) {
        username = argv[2];
    }
    if (argc > 3) {
        password = argv[3];
    }
    if (argc > 4) {
        sftppath = argv[4];
    }

    rc = libssh2_init(0);
    if (rc) {
        fprintf(stderr, "libssh2 initialization failed (%d)\n", rc);
        return 1;
    }

    /*
     * The application code is responsible for creating the socket and establishing the connection
     */
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == LIBSSH2_INVALID_SOCKET) {
        fprintf(stderr, "failed to create socket.\n");
        goto shutdown;
    }

    sin.sin_family = AF_INET;
    sin.sin_port = htons(22);
    sin.sin_addr.s_addr = hostaddr;
    if (connect(sock, (struct sockaddr *)(&sin), sizeof(struct sockaddr_in))) {
        fprintf(stderr, "failed to connect.\n");
        goto shutdown;
    }

    session = libssh2_session_init();/* Create a session instance */
    if (!session) {
        fprintf(stderr, "Could not initialize SSH session.\n");
        goto shutdown;
    }

    /* ... start it up. This will trade welcome banners, exchange keys,
     * and setup crypto, compression, and MAC layers
     */
    rc = libssh2_session_handshake(session, sock);
    if (rc) {
        fprintf(stderr, "Failure establishing SSH session: %d\n", rc);
        goto shutdown;
    }

    /* At this point we have not yet authenticated.  The first thing to do
     * is check the hostkey's fingerprint against our known hosts Your app
     * may have it hard coded, may go to a file, may present it to the user, that's your call
     */
    fingerprint = libssh2_hostkey_hash(session, LIBSSH2_HOSTKEY_HASH_SHA1);
    fprintf(stderr, "Fingerprint: ");
    for (i = 0; i < 20; i++) {
        fprintf(stderr, "%02X ", (unsigned char)fingerprint[i]);
    }
    fprintf(stderr, "\n");

    if (auth_pw) { /* We could authenticate via password */
        if (libssh2_userauth_password(session, username, password)) {
            fprintf(stderr, "Authentication by password failed.\n");
            goto shutdown;
        }
    } else {/* Or by public key */
        if (libssh2_userauth_publickey_fromfile(session, username, pubkey, privkey, password)) {
            fprintf(stderr, "Authentication by public key failed.\n");
            goto shutdown;
        }
    }

    if (0) {
        sftp_session = libssh2_sftp_init(session);
        if (!sftp_session) {
            fprintf(stderr, "Unable to init SFTP session\n");
            goto shutdown;
        }

        /* Since we have not set non-blocking, tell libssh2 we are blocking */
        libssh2_session_set_blocking(session, 1);

        /* Make a directory via SFTP */
        rc = libssh2_sftp_mkdir(sftp_session, sftppath,
                                LIBSSH2_SFTP_S_IRWXU |
                                LIBSSH2_SFTP_S_IRGRP |
                                LIBSSH2_SFTP_S_IXGRP |
                                LIBSSH2_SFTP_S_IROTH |
                                LIBSSH2_SFTP_S_IXOTH);
        if (rc)
            fprintf(stderr, "libssh2_sftp_mkdir failed: %d\n", rc);

        libssh2_sftp_shutdown(sftp_session);
    } else {
        /* Request a session channel on which to run a shell */
        LIBSSH2_CHANNEL * channel;
        //unsigned long xfer_bytes = 0;
        //char remote_command[256] = "echo test > /tmp/test.txt";//test ok
        char remote_command[256] = "pwd";

        channel = libssh2_channel_open_session(session);
        if (!channel) {
            fprintf(stderr, "Unable to open a session\n");
            goto shutdown;
        }

        /* Send the command to transfer data */
        if (libssh2_channel_exec(channel, remote_command)) {
            fprintf(stderr, "Unable to request command on channel\n");
            goto shutdown;
        }

        /* Read data */
        while (!libssh2_channel_eof(channel)) {
            char buf[1024] = {};
            ssize_t err = libssh2_channel_read(channel, buf, sizeof(buf));
            if (err < 0)
                fprintf(stderr, "Unable to read response: %d\n", (int)err);
            else {
                fprintf(stderr, "%s\n", buf);

                //unsigned int i;
                //for (i = 0; i < (unsigned long)err; ++i) {
                //    if (buf[i]) {
                //        //fprintf(stderr, "Bad data received\n");
                //        /* Test will fail below due to bad data length */                        
                //        break;
                //    }
                //}
                //xfer_bytes += i;
            }
        }

        /* Shut down */
        if (libssh2_channel_close(channel))
            fprintf(stderr, "Unable to close channel\n");

        if (channel) {
            libssh2_channel_free(channel);
            channel = NULL;
        }
    }

shutdown:

    if (session) {
        libssh2_session_disconnect(session, "Normal Shutdown");
        libssh2_session_free(session);
    }

    if (sock != LIBSSH2_INVALID_SOCKET) {
        shutdown(sock, 2);
    #ifdef WIN32
        closesocket(sock);
    #else
        close(sock);
    #endif
    }

    fprintf(stderr, "all done\n");

    libssh2_exit();

    return 0;
}
