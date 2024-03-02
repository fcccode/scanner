#include "test.h"
#include "udp.h"
#include "icmp.h"


int test()
{
    IN_ADDR DestinationAddress;
    DestinationAddress.S_un.S_addr = inet_addr("104.193.88.77");
    //Icmpv4Scan(&DestinationAddress);

    //Icmpv4Scan(&g_AdapterIPv4ddress, &DestinationAddress);

    IN6_ADDR sin6_addr;
    //InetPtonA(AF_INET6, "fe80::36ca:81ff:fe23:b43", &sin6_addr); //�������ڵ�һ����·���ص�ַ��
    //InetPtonA(AF_INET6, "240e:e9:6002:15c:0:ff:b015:146f", &sin6_addr);//�������ڵ�һ��ȫ��IPv6.
    InetPtonA(AF_INET6, "2603:1030:20e:3::23c", &sin6_addr);//���ǹȸ��IPv6����ǽ��ʧ�ܡ�
    //Icmpv6Scan(&sin6_addr);

    //Icmpv6Scan(&g_AdapterLinkLocalIPv6Address, &sin6_addr);
    Icmpv6Scan(IN6_IS_ADDR_GLOBAL(&sin6_addr) ? &g_AdapterGlobalIPv6Address : &g_AdapterLinkLocalIPv6Address, &sin6_addr);

    return ERROR_SUCCESS;
}
