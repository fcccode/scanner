/*
���ܣ�ICMPɨ�衣

�������ǿ���ICMPɨ�����Լ���װICMP
�������RAW�׽��֡��в���������ƭ��ȱ�㡣
�����API���磺IcmpSendEcho2��Icmp6SendEcho2��
*/

#pragma once

#include "pch.h"

int Icmpv4Scan(PIN_ADDR DstIPv4);
int Icmpv4Scan(PIN_ADDR SrcIPv4, PIN_ADDR DstIPv4);
int Icmpv4Scan(PIN_ADDR DstIPv4, BYTE Mask);
int Icmpv6Scan(PIN6_ADDR DstIPv6);
int Icmpv6Scan(PIN6_ADDR DstIPv6, BYTE Mask);
