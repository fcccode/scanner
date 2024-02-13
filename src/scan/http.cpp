#include "http.h"


int IsHttp(const char * ip, const char * port)
/*
功能：
1.检测是不是HTTP。
2.获取HTTP的详细信息。
3.

用法：
IsHttp("23.59.207.220", "80");
IsHttp("2600:1406:3c00:399::356e", "80");
*/
{
    WSADATA wsaData;
    int iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (iResult != 0) {
        printf("WSAStartup failed with error: %d\n", iResult);
        return 1;
    }

    int af = AF_MAX;
    IN6_ADDR ipv6;
    IN_ADDR ipv4;
    if (InetPtonA(AF_INET6, ip, &ipv6)) {
        af = AF_INET6;
    } else if (InetPtonA(AF_INET, ip, &ipv4)) {
        af = AF_INET;
    } else {
        printf("无效IP：%s\n", ip);
        return 0;
    }

    SOCKET ConnectSocket = INVALID_SOCKET;
    ConnectSocket = socket(af, SOCK_STREAM, IPPROTO_TCP);
    if (ConnectSocket == INVALID_SOCKET) {
        printf("socket failed with error: %ld\n", WSAGetLastError());
        WSACleanup();
        return 1;
    }

    sockaddr_in clientService{};
    sockaddr_in6 clientService6{};
    const struct sockaddr FAR * name;
    int namelen;

    if (AF_INET6 == af) {
        clientService6.sin6_family = (ADDRESS_FAMILY)af;
        clientService6.sin6_addr = ipv6;
        clientService6.sin6_port = htons((u_short)atoi(port));

        name = (const struct sockaddr FAR *)&clientService6;
        namelen = sizeof(sockaddr_in6);
    } else {
        clientService.sin_family = (ADDRESS_FAMILY)af;
        clientService.sin_addr.s_addr = inet_addr(ip);
        clientService.sin_port = htons((u_short)atoi(port));

        name = (const struct sockaddr FAR *) & clientService;
        namelen = sizeof(sockaddr_in);
    }

    iResult = connect(ConnectSocket, name, namelen);
    if (iResult == SOCKET_ERROR) {
        printf("connect failed with error: %ld\n", WSAGetLastError());//建议关闭代理，否则经常返回WSAETIMEDOUT。
        closesocket(ConnectSocket);
        ConnectSocket = INVALID_SOCKET;
        return 1;
    }

    if (ConnectSocket == INVALID_SOCKET) {
        printf("Unable to connect to server!\n");
        WSACleanup();
        return 1;
    }

    const char * sendbuf = "GET / HTTP/1.0\r\n\r\n";
    iResult = send(ConnectSocket, sendbuf, (int)strlen(sendbuf), 0);
    if (iResult == SOCKET_ERROR) {
        printf("send failed with error: %d\n", WSAGetLastError());
        closesocket(ConnectSocket);
        WSACleanup();
        return 1;
    }

    iResult = shutdown(ConnectSocket, SD_SEND);
    if (iResult == SOCKET_ERROR) {
        printf("shutdown failed with error: %d\n", WSAGetLastError());
        closesocket(ConnectSocket);
        WSACleanup();
        return 1;
    }

    //建议sleep以下，以防对方的信息还没有及时发送过来。

    do {// Receive until the peer closes the connection
        char recvbuf[512] = {0};
        iResult = recv(ConnectSocket, recvbuf, sizeof(recvbuf), 0);//如果服务端繁忙这里会等待,如调试,一般这里是不会等待的.
        if (iResult > 0) {
            printf("recv success.\n");
            printf("Bytes received: %d\n", iResult);
            printf("%s.\n", recvbuf);
        } else if (iResult == 0) {
            printf("Connection closed\n");
        } else {
            printf("recv failed with error: %d\n", WSAGetLastError());
        }
    } while (iResult > 0);

    closesocket(ConnectSocket);
    WSACleanup();
    return 0;
}
