#include "icmp.h"
#include <winternl.h>


//////////////////////////////////////////////////////////////////////////////////////////////////


int Icmpv4Scan(PIN_ADDR DstIPv4)
/*

测试样例代码：
    IN_ADDR DestinationAddress;
    DestinationAddress.S_un.S_addr = inet_addr("104.193.88.77");
    Icmpv4Scan(&DestinationAddress);
*/
{
    int ret = 0;
    HANDLE hIcmpFile;
    //unsigned long ipaddr = INADDR_NONE;
    DWORD dwRetVal = 0;
    DWORD dwError = 0;
    char SendData[] = "Data Buffer";
    LPVOID ReplyBuffer = NULL;
    DWORD ReplySize = 0;

    hIcmpFile = IcmpCreateFile();
    if (hIcmpFile == INVALID_HANDLE_VALUE) {
        printf("\tUnable to open handle.\n");
        printf("IcmpCreatefile returned error: %ld\n", GetLastError());
        return 1;
    }

    // Allocate space for a single reply.
    ReplySize = sizeof(ICMP_ECHO_REPLY) + sizeof(SendData) + 8;
    ReplyBuffer = (VOID *)malloc(ReplySize);
    if (ReplyBuffer == NULL) {
        printf("\tUnable to allocate memory for reply buffer\n");
        return 1;
    }

    dwRetVal = IcmpSendEcho2(hIcmpFile, NULL, NULL, NULL,
                             DstIPv4->S_un.S_addr, SendData, sizeof(SendData), NULL,
                             ReplyBuffer, ReplySize, 1000);
    if (dwRetVal != 0) {
        PICMP_ECHO_REPLY pEchoReply = (PICMP_ECHO_REPLY)ReplyBuffer;
        struct in_addr ReplyAddr;
        ReplyAddr.S_un.S_addr = pEchoReply->Address;
        //printf("\tSent icmp message to %s\n", argv[1]);
        if (dwRetVal > 1) {
            printf("\tReceived %ld icmp message responses\n", dwRetVal);
            printf("\tInformation from the first response:\n");
        } else {
            printf("\tReceived %ld icmp message response\n", dwRetVal);
            printf("\tInformation from this response:\n");
        }
        printf("\t  Received from %s\n", inet_ntoa(ReplyAddr));
        printf("\t  Status = %ld  ", pEchoReply->Status);
        switch (pEchoReply->Status) {
        case IP_DEST_HOST_UNREACHABLE:
            printf("(Destination host was unreachable)\n");
            break;
        case IP_DEST_NET_UNREACHABLE:
            printf("(Destination Network was unreachable)\n");
            break;
        case IP_REQ_TIMED_OUT:
            printf("(Request timed out)\n");
            break;
        default:
            printf("\n");
            break;
        }

        printf("\t  Roundtrip time = %ld milliseconds\n", pEchoReply->RoundTripTime);
    } else {
        printf("Call to IcmpSendEcho2 failed.\n");
        dwError = GetLastError();
        switch (dwError) {
        case IP_BUF_TOO_SMALL:
            printf("\tReplyBufferSize too small\n");
            break;
        case IP_REQ_TIMED_OUT:
            printf("\tRequest timed out\n");
            break;
        default:
            printf("\tExtended error returned: %ld\n", dwError);
            break;
        }

        return 1;
    }

    return ret;
}


int Icmpv4Scan(PIN_ADDR DstIPv4, BYTE Mask)
{
    int ret = 0;

    UNREFERENCED_PARAMETER(DstIPv4);
    UNREFERENCED_PARAMETER(Mask);

    return ret;
}


int Icmpv6Scan(PIN6_ADDR DstIPv6)
/*

测试样例代码：
    IN6_ADDR sin6_addr;
    InetPtonA(AF_INET6, "fe80::36ca:81ff:fe23:b43", &sin6_addr); //局域网内的一个链路本地地址。
    //InetPtonA(AF_INET6, "240e:390:8a0:f940:a09a:948a:3480:4479", &sin6_addr);//局域网内的一个全局IPv6.
    //InetPtonA(AF_INET6, "2603:1030:20e:3::23c", &sin6_addr);//谨记谷歌的IPv6不翻墙会失败。
    Icmpv6Scan(&sin6_addr);

局域网的和互联网的都测试成功。
*/
{
    int ret = 0;

    HANDLE hIcmpFile = Icmp6CreateFile();
    if (hIcmpFile == INVALID_HANDLE_VALUE) {
        printf("\tUnable to open handle.\n");
        printf("Icmp6Createfile returned error: %lu\n", GetLastError());
        return 0;
    }

    struct sockaddr_in6 SourceAddress = {0};
    //SourceAddress.sin6_addr = g_AdapterLinkLocalIPv6Address;
    SourceAddress.sin6_addr = g_AdapterGlobalIPv6Address;
    //SourceAddress.sin6_addr = in6addr_any;//这个更通用。
    SourceAddress.sin6_family = AF_INET6;

    struct sockaddr_in6 DestinationAddress = {0};
    DestinationAddress.sin6_addr = *DstIPv6;
    DestinationAddress.sin6_family = AF_INET6;

    unsigned char         optionsData[32]{};

    WORD                     RequestSize = sizeof(optionsData);
    IP_OPTION_INFORMATION  RequestOptions = {255, 0, 0, 0/*禁止为(UCHAR)RequestSize*/, optionsData};

    DWORD ReplySize = sizeof(ICMPV6_ECHO_REPLY) + RequestSize + 8 + sizeof(IO_STATUS_BLOCK);
    DWORD                    Timeout = 1000;

    PVOID ReplyBuffer = (PVOID)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, ReplySize);
    _ASSERTE(ReplyBuffer);

    ret = Icmp6SendEcho2(hIcmpFile,
                         nullptr,
                         nullptr,
                         nullptr,
                         &SourceAddress,
                         &DestinationAddress,
                         optionsData, //RequestData,
                         RequestSize,
                         &RequestOptions,
                         ReplyBuffer,
                         ReplySize,
                         Timeout);
    if (0 == ret) {
        printf("LastError:%lu\n", GetLastError());//ERROR_INVALID_PARAMETER
        IcmpCloseHandle(hIcmpFile);
        return 0;
    }

#pragma prefast( push )
#pragma prefast( disable: 28020, "表达式“_Param_(2)>sizeof(struct icmpv6_echo_reply_lh ICMPV6_ECHO_REPLY)+8”对此调用无效。" )
    ret = Icmp6ParseReplies(ReplyBuffer, ReplySize);
#pragma prefast( pop )     
    if (0 == ret) {
        printf("LastError:%lu\n", GetLastError());
        IcmpCloseHandle(hIcmpFile);
        return 0;
    }

    PICMPV6_ECHO_REPLY Reply = static_cast<PICMPV6_ECHO_REPLY>(ReplyBuffer);
    printf("Status:%lu\n", Reply->Status);

    HeapFree(GetProcessHeap(), 0, ReplyBuffer);
    IcmpCloseHandle(hIcmpFile);

    return ret;
}


int Icmpv6Scan(PIN6_ADDR DstIPv6, BYTE Mask)
{
    int ret = 0;

    UNREFERENCED_PARAMETER(DstIPv6);
    UNREFERENCED_PARAMETER(Mask);

    return ret;
}
