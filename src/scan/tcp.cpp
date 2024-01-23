#include "tcp.h"


//////////////////////////////////////////////////////////////////////////////////////////////////


void ParsePacket(struct pcap_pkthdr * header, const BYTE * pkt_data)
{
    PETHERNET_HEADER eth_hdr = (PETHERNET_HEADER)pkt_data;
    PRAW_TCP tcp4 = NULL;
    PRAW6_TCP tcp6 = NULL;

    UNREFERENCED_PARAMETER(header);

    switch (ntohs(eth_hdr->Type)) {
    case ETHERNET_TYPE_IPV4:
    {
        tcp4 = (PRAW_TCP)pkt_data;

        switch (tcp4->ip_hdr.Protocol) {
        case IPPROTO_TCP:
        {
            wchar_t SrcIp[46] = {0};
            wchar_t DesIp[46] = {0};

            InetNtop(AF_INET, &tcp4->ip_hdr.SourceAddress, SrcIp, _ARRAYSIZE(SrcIp));
            InetNtop(AF_INET, &tcp4->ip_hdr.DestinationAddress, DesIp, _ARRAYSIZE(DesIp));

            if ((tcp4->tcp_hdr.th_flags & TH_ACK) && (tcp4->tcp_hdr.th_flags & TH_SYN)) {
                printf("%ls:%d open.\n", SrcIp, ntohs(tcp4->tcp_hdr.th_sport));
            } else if (tcp4->tcp_hdr.th_flags & TH_RST) {
                //printf("%ls:%d close.\n", SrcIp, ntohs(tcp4->tcp_hdr.th_sport));//发送关闭操作，也可能是开的。
            } else {
                //printf("%ls:%d unknow.\n", SrcIp, ntohs(tcp4->tcp_hdr.th_sport));
            }

            break;
        }
        default:
            break;
        }

        break;
    }
    case ETHERNET_TYPE_IPV6:
    {
        tcp6 = (PRAW6_TCP)pkt_data;

        switch (tcp6->ip_hdr.NextHeader) {
        case IPPROTO_TCP:
        {
            wchar_t SrcIp[46];
            wchar_t DesIp[46];

            InetNtop(AF_INET6, &tcp6->ip_hdr.SourceAddress, SrcIp, _ARRAYSIZE(SrcIp));
            InetNtop(AF_INET6, &tcp6->ip_hdr.DestinationAddress, DesIp, _ARRAYSIZE(DesIp));

            if ((tcp6->tcp_hdr.th_flags & TH_ACK) && (tcp6->tcp_hdr.th_flags & TH_SYN)) {
                printf("%ls:%d open.\n", SrcIp, ntohs(tcp6->tcp_hdr.th_sport));
            } else if (tcp6->tcp_hdr.th_flags & TH_RST) {
                //printf("%ls:%d close.\n", SrcIp, ntohs(tcp6->tcp_hdr.th_sport));//发送关闭操作，也可能是开的。
            } else {
                //printf("%ls:%d unknow.\n", SrcIp, ntohs(tcp6->tcp_hdr.th_sport));
            }

            break;
        }
        default:
            break;
        }

        break;
    }
    default:
        break;
    }
}


void SendSyn4(pcap_t * fp,
              PUINT8 SrcMac,
              PBYTE DesMac,
              PIN_ADDR SourceAddress,
              PIN_ADDR DestinationAddress,
              WORD RemotePort
)
/*
功能：通过IPv4发送一个TCP的SYN。

可以考虑再进一步的封装：SynScan4，只支持扫描，不支持攻击和欺骗。

注释：发送一个SYN，一般会回3个ACK+SYN和一个RST.
*/
{
    BYTE buffer[sizeof(RAW_TCP) + sizeof(TCP_OPT_MSS)] = {0};

    PacketizeSyn4(SrcMac,
                  DesMac,
                  SourceAddress,
                  DestinationAddress,
                  htons((WORD)RangedRand(3072, MAXWORD)),
                  htons(RemotePort),
                  buffer);

    /*
    提示：
    1.masscan是发送一次。
    2.nmap是发两次。有的会放弃/忽略第一次。
    3.
    */
    //for (int i = 0; i < 2; i++) {
    if (pcap_sendpacket(fp, (const u_char *)buffer, sizeof(buffer)) != 0) {
        fprintf(stderr, "\nError sending the packet: %s\n", pcap_geterr(fp));
        return;
    }
    //}
}


void SendSyn6(pcap_t * fp,
              PUINT8 SrcMac,
              PBYTE DesMac,
              PIN6_ADDR SourceAddress,
              PIN6_ADDR DestinationAddress,
              WORD RemotePort
)
{
    BYTE buffer[sizeof(RAW6_TCP)] = {0};// + sizeof(TCP_OPT_MSS)
    WORD LocalPort = (WORD)RangedRand(3072, MAXWORD);

    PacketizeSyn6(SrcMac,
                  DesMac,
                  SourceAddress,
                  DestinationAddress,
                  htons(LocalPort),
                  RemotePort,
                  buffer);

    if (pcap_sendpacket(fp, (const u_char *)buffer, sizeof(buffer)) != 0) {
        fprintf(stderr, "\nError sending the packet: %s\n", pcap_geterr(fp));
        return;
    }//发送一个SYN，一般会回3个ACK+SYN和一个RST.
}


//以上是核心代码。
//////////////////////////////////////////////////////////////////////////////////////////////////
//以下是测试代码。


void Syn4ScanTest(const char * source, const char * RemoteIPv4, WORD RemotePort)
/*
功能：发送SYN的TCP包。

参考：npcap-sdk-1.07\Examples-remote\misc\sendpack.c
*/
{
    pcap_t * fp;
    int snaplen = sizeof(RAW_TCP) + sizeof(TCP_OPT_MSS);
    char errbuf[PCAP_ERRBUF_SIZE];
    if ((fp = pcap_open(source,				// name of the device
                        snaplen,// portion of the packet to capture
                        PCAP_OPENFLAG_PROMISCUOUS, 	// promiscuous mode
                        1,				    // read timeout
                        NULL,				// authentication on the remote machine
                        errbuf				// error buffer
    )) == NULL) {
        fprintf(stderr, "\nUnable to open the adapter. %s is not supported by Npcap\n", source);
        return;
    }

    UINT8 SrcMac[6];
    GetMacAddress(source, SrcMac);

    IN_ADDR SourceAddress;
    GetOneAddress(source, &SourceAddress, NULL, NULL);

    IN_ADDR DestinationAddress;
    DestinationAddress.S_un.S_addr = inet_addr(RemoteIPv4);

    UINT8 DesMac[6];
    GetGatewayMacByIPv4(inet_ntoa(SourceAddress), DesMac);

    SendSyn4(fp, SrcMac, DesMac, &SourceAddress, &DestinationAddress, RemotePort);

    UINT res;
    struct pcap_pkthdr * header;
    const BYTE * pkt_data;
    while ((res = pcap_next_ex(fp, &header, &pkt_data)) >= 0) {
        if (res == 0)
            continue;

        if (pkt_data) {
            ParsePacket(header, pkt_data);
        }
    }
}


void Syn4ScanTest0(const char * source, const char * RemoteIPv4, WORD RemotePort)
/*
功能：发送SYN的TCP包。

参考：npcap-sdk-1.07\Examples-remote\misc\sendpack.c
*/
{
    pcap_t * fp;
    char errbuf[PCAP_ERRBUF_SIZE];
    BYTE buffer[sizeof(RAW_TCP) + sizeof(TCP_OPT_MSS)] = {0};
    //PRAW_TCP Syn4 = (PRAW_TCP)buffer;
    if ((fp = pcap_open(source,				// name of the device
                        sizeof(buffer),				// portion of the packet to capture (only the first 100 bytes)
                        PCAP_OPENFLAG_PROMISCUOUS, 	// promiscuous mode
                        1,				    // read timeout
                        NULL,				// authentication on the remote machine
                        errbuf				// error buffer
    )) == NULL) {
        fprintf(stderr, "\nUnable to open the adapter. %s is not supported by Npcap\n", source);
        return;
    }

    UINT8 SrcMac[6];
    GetMacAddress(source, SrcMac);

    IN_ADDR SourceAddress;
    GetOneAddress(source, &SourceAddress, NULL, NULL);

    IN_ADDR DestinationAddress;
    DestinationAddress.S_un.S_addr = inet_addr(RemoteIPv4);

    WORD LocalPort = (WORD)RangedRand(3072, MAXWORD);

    UINT8 DesMac[6];
    GetGatewayMacByIPv4(inet_ntoa(SourceAddress), DesMac);

    PacketizeSyn4(SrcMac,
                  DesMac,
                  &SourceAddress,
                  &DestinationAddress,
                  htons(LocalPort),
                  htons(RemotePort),
                  buffer);

    /* Send down the packet */
    if (pcap_sendpacket(fp, (const u_char *)buffer, sizeof(buffer)) != 0) {
        fprintf(stderr, "\nError sending the packet: %s\n", pcap_geterr(fp));
        return;
    }//发送一个SYN，一般会回3个ACK+SYN和一个RST.

    UINT res;
    struct pcap_pkthdr * header;
    const BYTE * pkt_data;
    while ((res = pcap_next_ex(fp, &header, &pkt_data)) >= 0) {
        if (res == 0)
            continue;

        if (pkt_data) {
            ParsePacket(header, pkt_data);
        }
    }
}


void Syn6ScanTest(const char * source, const char * RemoteIPv6, WORD RemotePort)
/*
功能：发送SYN的TCP包。

参考：npcap-sdk-1.07\Examples-remote\misc\sendpack.c

注意：互联网扫描和局域网扫描要用不同的网卡。
如：互联网要用有互联网地址（IPv6）的网卡。
局域网扫描也要选不同的网卡，如：vmware虚拟机和hy-v虚拟机。
*/
{
    /* Open the output device */
    pcap_t * fp;
    char errbuf[PCAP_ERRBUF_SIZE];
    BYTE buffer[sizeof(RAW6_TCP)] = {0};// + sizeof(TCP_OPT_MSS)
    if ((fp = pcap_open(source,				// name of the device
                        sizeof(buffer),				// portion of the packet to capture (only the first 100 bytes)
                        PCAP_OPENFLAG_PROMISCUOUS, 	// promiscuous mode
                        1,				    // read timeout
                        NULL,				// authentication on the remote machine
                        errbuf				// error buffer
    )) == NULL) {
        fprintf(stderr, "\nUnable to open the adapter. %s is not supported by Npcap\n", source);
        return;
    }

    UINT8 SrcMac[6];
    GetMacAddress(source, SrcMac);

    IN6_ADDR LinkLocalIPv6Address = IN6ADDR_ANY_INIT;
    IN6_ADDR GlobalIPv6Address = IN6ADDR_ANY_INIT;
    GetOneAddress(source, NULL, &LinkLocalIPv6Address, &GlobalIPv6Address);

    DWORD ipbufferlength = 46;
    char ipstringbuffer[46] = {0};
    inet_ntop(AF_INET6, &LinkLocalIPv6Address, ipstringbuffer, ipbufferlength);

    IN6_ADDR DestinationAddress = IN6ADDR_ANY_INIT;
    InetPtonA(AF_INET6, RemoteIPv6, &DestinationAddress);

    if (IN6_IS_ADDR_LINKLOCAL(&DestinationAddress)) {
        if (IN6_IS_ADDR_UNSPECIFIED(&LinkLocalIPv6Address)) {
            fprintf(stderr, "本网卡没有本地IPv6地址，不能进行IPv6局域网扫描\n");
            return;
        }
    }

    if (IN6_IS_ADDR_GLOBAL(&DestinationAddress)) {
        if (IN6_IS_ADDR_UNSPECIFIED(&GlobalIPv6Address)) {
            fprintf(stderr, "本网卡没有互联网IPv6地址，不能进行IPv6互联网扫描\n");
            return;
        }
    }    

    UINT8 DesMac[6] = {0};

    if (IN6_IS_ADDR_LINKLOCAL(&DestinationAddress)) {
        GetMacByIPv6(RemoteIPv6, DesMac);
        if (DesMac[0] == 0 && DesMac[1] == 0 && DesMac[2] == 0 &&
            DesMac[3] == 0 && DesMac[4] == 0 && DesMac[5] == 0) {
            fprintf(stderr, "没有获取到本网卡的网关的物理地址，扫描退出\n");
            return;//IPv6的互联网和局域网扫描必须都有目的MAC。
        }
    }

    if (IN6_IS_ADDR_GLOBAL(&DestinationAddress)) {
        GetGatewayMacByIPv6(ipstringbuffer, DesMac);
        if (DesMac[0] == 0 && DesMac[1] == 0 && DesMac[2] == 0 &&
            DesMac[3] == 0 && DesMac[4] == 0 && DesMac[5] == 0) {
            fprintf(stderr, "没有获取到本网卡的网关的物理地址，扫描退出\n");
            return;//IPv6的互联网和局域网扫描必须都有目的MAC。
        }
    }

    SendSyn6(fp,
             SrcMac,
             DesMac,
             IN6_IS_ADDR_LINKLOCAL(&DestinationAddress) ? &LinkLocalIPv6Address : &GlobalIPv6Address,
             &DestinationAddress,
             htons(RemotePort));

    UINT res;
    struct pcap_pkthdr * header;
    const BYTE * pkt_data;
    while ((res = pcap_next_ex(fp, &header, &pkt_data)) >= 0) {
        if (res == 0)
            continue;

        if (pkt_data) {
            ParsePacket(header, pkt_data);
        }
    }
}


void Syn6ScanTest0(const char * source, const char * RemoteIPv6, WORD RemotePort)
/*
功能：发送SYN的TCP包。

参考：npcap-sdk-1.07\Examples-remote\misc\sendpack.c
*/
{
    /* Open the output device */
    pcap_t * fp;
    char errbuf[PCAP_ERRBUF_SIZE];
    BYTE buffer[sizeof(RAW6_TCP)] = {0};// + sizeof(TCP_OPT_MSS)
    //PRAW_TCP Syn4 = (PRAW_TCP)buffer;
    if ((fp = pcap_open(source,				// name of the device
                        sizeof(buffer),				// portion of the packet to capture (only the first 100 bytes)
                        PCAP_OPENFLAG_PROMISCUOUS, 	// promiscuous mode
                        1,				    // read timeout
                        NULL,				// authentication on the remote machine
                        errbuf				// error buffer
    )) == NULL) {
        fprintf(stderr, "\nUnable to open the adapter. %s is not supported by Npcap\n", source);
        return;
    }

    UINT8 SrcMac[6];
    GetMacAddress(source, SrcMac);

    IN6_ADDR LinkLocalIPv6Address = IN6ADDR_ANY_INIT;
    IN6_ADDR GlobalIPv6Address = IN6ADDR_ANY_INIT;
    GetOneAddress(source, NULL, &LinkLocalIPv6Address, &GlobalIPv6Address);

    DWORD ipbufferlength = 46;
    char ipstringbuffer[46] = {0};
    inet_ntop(AF_INET6, &LinkLocalIPv6Address, ipstringbuffer, ipbufferlength);

    IN6_ADDR DestinationAddress = IN6ADDR_ANY_INIT;
    InetPtonA(AF_INET6, RemoteIPv6, &DestinationAddress);

    if (IN6_IS_ADDR_LINKLOCAL(&DestinationAddress)) {
        if (IN6_IS_ADDR_UNSPECIFIED(&LinkLocalIPv6Address)) {
            fprintf(stderr, "本网卡没有本地IPv6地址，不能进行IPv6局域网扫描\n");
            return;
        }
    }

    if (IN6_IS_ADDR_GLOBAL(&DestinationAddress)) {
        if (IN6_IS_ADDR_UNSPECIFIED(&GlobalIPv6Address)) {
            fprintf(stderr, "本网卡没有互联网IPv6地址，不能进行IPv6互联网扫描\n");
            return;
        }
    }

    WORD LocalPort = (WORD)RangedRand(3072, MAXWORD);

    UINT8 DesMac[6] = {0};
    GetGatewayMacByIPv6(ipstringbuffer, DesMac);
    if (DesMac[0] == 0 && DesMac[1] == 0 && DesMac[2] == 0 &&
        DesMac[3] == 0 && DesMac[4] == 0 && DesMac[5] == 0) {
        fprintf(stderr, "没有获取到本网卡的网关的物理地址，扫描退出\n");
        return;
    }

    PacketizeSyn6(SrcMac,
                  DesMac,
                  IN6_IS_ADDR_LINKLOCAL(&DestinationAddress) ? &LinkLocalIPv6Address : &GlobalIPv6Address,
                  &DestinationAddress,
                  htons(LocalPort),
                  htons(RemotePort),
                  buffer);

    if (pcap_sendpacket(fp, (const u_char *)buffer, sizeof(buffer) /* size */) != 0) {
        fprintf(stderr, "\nError sending the packet: %s\n", pcap_geterr(fp));
        return;
    }//发送一个SYN，一般会回3个ACK+SYN和一个RST.

    UINT res;
    struct pcap_pkthdr * header;
    const BYTE * pkt_data;
    while ((res = pcap_next_ex(fp, &header, &pkt_data)) >= 0) {
        if (res == 0)
            continue;

        if (pkt_data) {
            ParsePacket(header, pkt_data);
        }
    }
}


//////////////////////////////////////////////////////////////////////////////////////////////////
