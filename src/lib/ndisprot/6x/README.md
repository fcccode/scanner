---
page_type: sample
description: "Demonstrates a connection-less NDIS 6.0 protocol WDM driver."
languages:
- cpp
products:
- windows
- windows-wdk
---

# NDIS Connection-less Protocol WDM Driver Sample

This sample demonstrates a connection-less NDIS 6.0 protocol WDM driver. The driver supports sending and receiving raw Ethernet frames using `ReadFile`/`WriteFile` calls from user-mode. It only receives frames with a specific EtherType field. As an NDIS protocol, it illustrates how to establish and tear down bindings to Ethernet adapters, i.e. those that export medium type **NdisMedium802\_3**. It shows how to set a packet filter, send and receive data, and handle plug-and-play events.

## Installation

The driver is installed using the INF file ndisprot.inf, which is provided in the driver directory. In Network Connections UI, select an adapter and open **Properties.**

Click **Install**, then **Protocol**, then **Add**, and then **Have disk**. Then point to the location of the .inf and driver.

Select **Sample NDIS Protocol Driver** and click **OK**. After installing the protocol, copy over the test application prottest.exe to a convenient location. Please note that the driver service has been set to manual start in the INF file. As a result, it doesn't get loaded automatically when you install.

## Usage

To start the driver, type `Net start ndisprot`.

To stop the driver, type `Net stop ndisprot`.

To test the driver, run `prottest`. For help on usage, run `prottest -?`

**usage: PROTTEST [options] \\*devicename***

| Options | description |
| --- | --- |
| -e | Enumerate devices |
| -r | Read |
| -w | Write (default) |
| -l | <length>: length of each packet (default: 100) |
| -n | <count>: number of packets (defaults to infinity) |
| -m | <MAC address> (defaults to local MAC) |

Prottest exercises the IOCTLs supported by NDISPROT, and sends and/or receives data on the selected device. In order to use prottest, the user must have administrative privilege. Users should pass down a big enough buffer in order to receive the entire received data. If the length of the buffer passed down is smaller than the length of the received data, NDISPROT will only copy part of the data and discard the rest when the given buffer is full.

Use the **-e** option to enumerate all devices to which NDISPROT is bound:

```cmd
C:\\prot\>prottest -n 2 \\DEVICE\\{9273DA7D-5275-4B9A-AC56-68A49D121F1F}
DoWriteProc: finished sending 2 packets of 100 bytes each
DoReadProc finished: read 2 packets
```

> [!NOTE]
> With a checked version of ndisprot.sys, you can control the volume of debug information generated by changing the variable `ndisprotDebugLevel`. Refer to debug.h for more information.

For more information, see [NDIS Protocol Drivers](https://docs.microsoft.com/windows-hardware/drivers/network/ndis-protocol-drivers) in the network devices design guide.

## File Manifest

| File | description |
| --- | --- |
| prottest.c | User-mode test application |
| debug.c | Routines to aid debugging |
| debug.h | Debug macro definitions |
| macros.h | Spinlock, event, referencing macros |
| ndisbind.c | NDIS protocol entry points to handle binding/unbinding from adapters |
| ndisprot.h | Data structure definitions |
| ndisprot.inf | INF file for installing NDISPROT |
| ntdisp.c | NT Entry points and dispatch routines for NDISPROT |
| protuser.h | IOCTL and associated structure definitions |
| recv.c | NDIS protocol entry points for receiving data, and IRP_MJ_READ processing |
| send.c | NDIS protocol routines for sending data, and IRP_MJ_WRITE processing |
