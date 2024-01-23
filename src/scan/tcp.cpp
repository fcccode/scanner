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
                //printf("%ls:%d close.\n", SrcIp, ntohs(tcp4->tcp_hdr.th_sport));//���͹رղ�����Ҳ�����ǿ��ġ�
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
                //printf("%ls:%d close.\n", SrcIp, ntohs(tcp6->tcp_hdr.th_sport));//���͹رղ�����Ҳ�����ǿ��ġ�
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
���ܣ�ͨ��IPv4����һ��TCP��SYN��

���Կ����ٽ�һ���ķ�װ��SynScan4��ֻ֧��ɨ�裬��֧�ֹ�������ƭ��

ע�ͣ�����һ��SYN��һ����3��ACK+SYN��һ��RST.
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
    ��ʾ��
    1.masscan�Ƿ���һ�Ρ�
    2.nmap�Ƿ����Ρ��еĻ����/���Ե�һ�Ρ�
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
    }//����һ��SYN��һ����3��ACK+SYN��һ��RST.
}


//�����Ǻ��Ĵ��롣
//////////////////////////////////////////////////////////////////////////////////////////////////
//�����ǲ��Դ��롣


void Syn4ScanTest(const char * source, const char * RemoteIPv4, WORD RemotePort)
/*
���ܣ�����SYN��TCP����

�ο���npcap-sdk-1.07\Examples-remote\misc\sendpack.c
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
���ܣ�����SYN��TCP����

�ο���npcap-sdk-1.07\Examples-remote\misc\sendpack.c
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
    }//����һ��SYN��һ����3��ACK+SYN��һ��RST.

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
���ܣ�����SYN��TCP����

�ο���npcap-sdk-1.07\Examples-remote\misc\sendpack.c

ע�⣺������ɨ��;�����ɨ��Ҫ�ò�ͬ��������
�磺������Ҫ���л�������ַ��IPv6����������
������ɨ��ҲҪѡ��ͬ���������磺vmware�������hy-v�������
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
            fprintf(stderr, "������û�б���IPv6��ַ�����ܽ���IPv6������ɨ��\n");
            return;
        }
    }

    if (IN6_IS_ADDR_GLOBAL(&DestinationAddress)) {
        if (IN6_IS_ADDR_UNSPECIFIED(&GlobalIPv6Address)) {
            fprintf(stderr, "������û�л�����IPv6��ַ�����ܽ���IPv6������ɨ��\n");
            return;
        }
    }    

    UINT8 DesMac[6] = {0};

    if (IN6_IS_ADDR_LINKLOCAL(&DestinationAddress)) {
        GetMacByIPv6(RemoteIPv6, DesMac);
        if (DesMac[0] == 0 && DesMac[1] == 0 && DesMac[2] == 0 &&
            DesMac[3] == 0 && DesMac[4] == 0 && DesMac[5] == 0) {
            fprintf(stderr, "û�л�ȡ�������������ص������ַ��ɨ���˳�\n");
            return;//IPv6�Ļ������;�����ɨ����붼��Ŀ��MAC��
        }
    }

    if (IN6_IS_ADDR_GLOBAL(&DestinationAddress)) {
        GetGatewayMacByIPv6(ipstringbuffer, DesMac);
        if (DesMac[0] == 0 && DesMac[1] == 0 && DesMac[2] == 0 &&
            DesMac[3] == 0 && DesMac[4] == 0 && DesMac[5] == 0) {
            fprintf(stderr, "û�л�ȡ�������������ص������ַ��ɨ���˳�\n");
            return;//IPv6�Ļ������;�����ɨ����붼��Ŀ��MAC��
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
���ܣ�����SYN��TCP����

�ο���npcap-sdk-1.07\Examples-remote\misc\sendpack.c
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
            fprintf(stderr, "������û�б���IPv6��ַ�����ܽ���IPv6������ɨ��\n");
            return;
        }
    }

    if (IN6_IS_ADDR_GLOBAL(&DestinationAddress)) {
        if (IN6_IS_ADDR_UNSPECIFIED(&GlobalIPv6Address)) {
            fprintf(stderr, "������û�л�����IPv6��ַ�����ܽ���IPv6������ɨ��\n");
            return;
        }
    }

    WORD LocalPort = (WORD)RangedRand(3072, MAXWORD);

    UINT8 DesMac[6] = {0};
    GetGatewayMacByIPv6(ipstringbuffer, DesMac);
    if (DesMac[0] == 0 && DesMac[1] == 0 && DesMac[2] == 0 &&
        DesMac[3] == 0 && DesMac[4] == 0 && DesMac[5] == 0) {
        fprintf(stderr, "û�л�ȡ�������������ص������ַ��ɨ���˳�\n");
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
    }//����һ��SYN��һ����3��ACK+SYN��һ��RST.

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
