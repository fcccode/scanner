/*
功能：ICMP扫描。

最基本和强大的ICMP扫描是自己组装ICMP，其次是用API。
*/

#pragma once

#include "pch.h"

int Icmpv4Scan(PIN_ADDR DstIPv4);
int Icmpv4Scan(PIN_ADDR DstIPv4, BYTE Mask);
int Icmpv6Scan(PIN6_ADDR DstIPv6);
int Icmpv6Scan(PIN6_ADDR DstIPv6, BYTE Mask);
