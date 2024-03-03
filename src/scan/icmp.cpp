#include "icmp.h"
#include <winternl.h>


//////////////////////////////////////////////////////////////////////////////////////////////////


void InitEthernetHeader(IN PBYTE SrcMac, IN PBYTE DesMac, IN UINT16 Type, OUT PETHERNET_HEADER eth_hdr)
/*
功能：填写以太头。

参数：
Type，取值，如：ETHERNET_TYPE_IPV4，ETHERNET_TYPE_IPV6， ETHERNET_TYPE_ARP等。

注释：
1.填写虚假的目的MAC，也可发送出去。
2.如果是想接收包，还是建议填写正确的目标的MAC（局域网的）.
3.这个MAC需要计算，如网关的MAC。
*/
{
    eth_hdr->Destination.Byte[0] = DesMac[0];
    eth_hdr->Destination.Byte[1] = DesMac[1];
    eth_hdr->Destination.Byte[2] = DesMac[2];
    eth_hdr->Destination.Byte[3] = DesMac[3];
    eth_hdr->Destination.Byte[4] = DesMac[4];
    eth_hdr->Destination.Byte[5] = DesMac[5];

    eth_hdr->Source.Byte[0] = SrcMac[0];
    eth_hdr->Source.Byte[1] = SrcMac[1];
    eth_hdr->Source.Byte[2] = SrcMac[2];
    eth_hdr->Source.Byte[3] = SrcMac[3];
    eth_hdr->Source.Byte[4] = SrcMac[4];
    eth_hdr->Source.Byte[5] = SrcMac[5];

    eth_hdr->Type = ntohs(Type);
}


void InitIpv4Header(IN PIN_ADDR SourceAddress,
                    IN PIN_ADDR DestinationAddress,
                    IN UINT8 Protocol, //取值，如：IPPROTO_TCP等。
                    IN UINT16 TotalLength,//严格计算数据的大小。
                    OUT PIPV4_HEADER IPv4Header
)
/*
功能：组装IPv4头。
*/
{
    IPv4Header->VersionAndHeaderLength = (4 << 4) | (sizeof(IPV4_HEADER) / sizeof(unsigned long));
    IPv4Header->TotalLength = ntohs(TotalLength);
    IPv4Header->Identification = ntohs(0);
    IPv4Header->DontFragment = TRUE;
    IPv4Header->TimeToLive = 128;
    IPv4Header->Protocol = Protocol;
    IPv4Header->SourceAddress.S_un.S_addr = SourceAddress->S_un.S_addr;
    IPv4Header->DestinationAddress.S_un.S_addr = DestinationAddress->S_un.S_addr;
    IPv4Header->HeaderChecksum = checksum(reinterpret_cast<unsigned short *>(IPv4Header), sizeof(IPV4_HEADER));
}


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


int Icmpv4Scan(PIN_ADDR SrcIPv4, PIN_ADDR DstIPv4)
{
    BYTE icmpv4_echo_request[sizeof(ETHERNET_HEADER) + sizeof(IPV4_HEADER) + sizeof(ICMP_MESSAGE)]{};

    packetize_icmpv4_echo_request(g_ActivityAdapterMac, g_AdapterGatewayMac, SrcIPv4, DstIPv4, icmpv4_echo_request);

    pcap_t * fp;
    char errbuf[PCAP_ERRBUF_SIZE];
    if ((fp = pcap_open(g_ActivityAdapterName.c_str(),				// name of the device
                        sizeof(icmpv4_echo_request),				// portion of the packet to capture (only the first 100 bytes)
                        PCAP_OPENFLAG_PROMISCUOUS, 	// promiscuous mode
                        1,				    // read timeout
                        NULL,				// authentication on the remote machine
                        errbuf				// error buffer
    )) == NULL) {
        fprintf(stderr, "\nUnable to open the adapter. %s is not supported by Npcap\n", g_ActivityAdapterName.c_str());
        return 0;
    }

    if (pcap_sendpacket(fp, (const u_char *)icmpv4_echo_request, sizeof(icmpv4_echo_request)) != 0) {
        fprintf(stderr, "\nError sending the packet: %s\n", pcap_geterr(fp));
        return 0;
    }

    return 0;
}


int Icmpv4Scan(PIN_ADDR DstIPv4, BYTE Mask)
{
    int ret = 0;

    UNREFERENCED_PARAMETER(DstIPv4);
    UNREFERENCED_PARAMETER(Mask);

    return ret;
}


//////////////////////////////////////////////////////////////////////////////////////////////////


void calculation_icmpv6_echo_request_checksum(OUT PBYTE buffer, IN int OptLen)
/*


数据结构的布局是：sizeof(ETHERNET_HEADER) + sizeof(IPV6_HEADER) + sizeof(ICMP_MESSAGE) + 0x20
*/
{
    UNREFERENCED_PARAMETER(OptLen);

    PIPV6_HEADER ip_hdr = (PIPV6_HEADER)(buffer + sizeof(ETHERNET_HEADER));
    PICMP_MESSAGE icmp_message = (PICMP_MESSAGE)(buffer + sizeof(ETHERNET_HEADER) + sizeof(IPV6_HEADER));

    BYTE temp[sizeof(PSD6_HEADER) + sizeof(ICMP_MESSAGE) + 0x20]{};

    PSD6_HEADER * PseudoHeader = reinterpret_cast<PSD6_HEADER *>(temp);
    RtlCopyMemory(&PseudoHeader->saddr, &ip_hdr->SourceAddress, sizeof(IN6_ADDR));
    RtlCopyMemory(&PseudoHeader->daddr, &ip_hdr->DestinationAddress, sizeof(IN6_ADDR));
    PseudoHeader->length = ntohl(sizeof(ICMP_MESSAGE) + 0x20);
    PseudoHeader->unused1 = 0;
    PseudoHeader->unused2 = 0;
    PseudoHeader->unused3 = 0;
    PseudoHeader->proto = IPPROTO_ICMPV6;

    PBYTE test = temp + sizeof(PSD6_HEADER);
    RtlCopyMemory(test, icmp_message, sizeof(ICMP_MESSAGE) + 0x20);

    icmp_message->Header.Checksum = checksum(reinterpret_cast<USHORT *>(temp), sizeof(temp));
}



void InitIpv6Header(IN PIN6_ADDR SourceAddress,
                    IN PIN6_ADDR DestinationAddress,
                    IN UINT8 NextHeader, //取值，如：IPPROTO_TCP等。
                    IN UINT16 OptLen,
                    OUT PIPV6_HEADER IPv6Header
)
/*

*/
{
    IPv6Header->VersionClassFlow = ntohl((6 << 28) | (0 << 20) | 0);// IPv6 version (4 bits), Traffic class (8 bits), Flow label (20 bits)
    IPv6Header->PayloadLength = ntohs(OptLen);
    IPv6Header->NextHeader = NextHeader;
    IPv6Header->HopLimit = 128;//128 64

    RtlCopyMemory(&IPv6Header->SourceAddress, SourceAddress, sizeof(IN6_ADDR));
    RtlCopyMemory(&IPv6Header->DestinationAddress, DestinationAddress, sizeof(IN6_ADDR));
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


void WINAPI packetize_icmpv6_echo_request_test(IN PBYTE SrcMac,    //6字节长的本地的MAC。
                                               IN PBYTE DesMac,
                                               IN PIN6_ADDR SourceAddress,
                                               IN PIN6_ADDR DestinationAddress,
                                               OUT PBYTE buffer//长度是sizeof(ETHERNET_HEADER) + sizeof(IPV6_HEADER) + sizeof(ICMP_MESSAGE) + 0x20
)
{
    //BYTE icmpv4_echo_request[sizeof(ETHERNET_HEADER) + sizeof(IPV6_HEADER) + sizeof(ICMP_MESSAGE)]{};//可以再附加数据。

    InitEthernetHeader(SrcMac, DesMac, ETHERNET_TYPE_IPV6, (PETHERNET_HEADER)buffer);

    InitIpv6Header(SourceAddress,
                   DestinationAddress,
                   IPPROTO_ICMPV6,
                   sizeof(ICMP_MESSAGE) + 0x20,
                   (PIPV6_HEADER)(buffer + sizeof(ETHERNET_HEADER)));

    PICMP_MESSAGE icmp_message = (PICMP_MESSAGE)(buffer + sizeof(ETHERNET_HEADER) + sizeof(IPV6_HEADER));
    icmp_message->Header.Type = ICMP6_ECHO_REQUEST;
    icmp_message->Header.Code = 0;
    icmp_message->Header.Checksum = 0;
    icmp_message->icmp6_id = (USHORT)GetCurrentProcessId();//htons(0xbc44);// 
    icmp_message->icmp6_seq = (USHORT)GetTickCount64();  //htons(0xb3);
    //icmp_message->Header.Checksum = 
    calculation_icmpv6_echo_request_checksum(buffer, sizeof(ETHERNET_HEADER) + sizeof(IPV6_HEADER) + sizeof(ICMP_MESSAGE) + 0x20);
}


int Icmpv6Scan(PIN6_ADDR SrcIPv6, PIN6_ADDR DstIPv6)
{
    BYTE Tmp[sizeof(ETHERNET_HEADER) + sizeof(IPV6_HEADER) + sizeof(ICMP_MESSAGE) + 0x20]{};

    memset(Tmp + sizeof(ETHERNET_HEADER) + sizeof(IPV6_HEADER) + sizeof(ICMP_MESSAGE), '#', 0x20);

    packetize_icmpv6_echo_request_test(g_ActivityAdapterMac, g_AdapterGatewayMac, SrcIPv6, DstIPv6, Tmp);
    /*
    这个包也发送成功了，对方也回了，
    但是操作系统又发送一个：icmpv6 "parameter problem" "unrecognized Next Header type encountered"
    包组装的没问题，应该是别处的代码或设置的问题，因为同样的包，也会出现这个问题。
    */

    pcap_t * fp;
    char errbuf[PCAP_ERRBUF_SIZE];
    if ((fp = pcap_open(g_ActivityAdapterName.c_str(), 
                        sizeof(Tmp),				// portion of the packet to capture (only the first 100 bytes)
                        PCAP_OPENFLAG_PROMISCUOUS, 	// promiscuous mode
                        1,				    // read timeout
                        NULL,				// authentication on the remote machine
                        errbuf				// error buffer
    )) == NULL) {
        fprintf(stderr, "\nUnable to open the adapter. %s is not supported by Npcap\n", g_ActivityAdapterName.c_str());
        return 0;
    }

    if (pcap_sendpacket(fp, (const u_char *)Tmp, sizeof(Tmp)) != 0) {
        fprintf(stderr, "\nError sending the packet: %s\n", pcap_geterr(fp));
        return 0;
    }

    return 0;
}


int Icmpv6Scan(PIN6_ADDR DstIPv6, BYTE Mask)
{
    int ret = 0;

    UNREFERENCED_PARAMETER(DstIPv6);
    UNREFERENCED_PARAMETER(Mask);

    return ret;
}


//////////////////////////////////////////////////////////////////////////////////////////////////
