/*
���ܣ�ICMPɨ�衣

�������ǿ���ICMPɨ�����Լ���װICMP���������API��
*/

#pragma once

#include "pch.h"

int Icmpv4Scan(PIN_ADDR DstIPv4);
int Icmpv4Scan(PIN_ADDR DstIPv4, BYTE Mask);
int Icmpv6Scan(PIN6_ADDR DstIPv6);
int Icmpv6Scan(PIN6_ADDR DstIPv6, BYTE Mask);
