/*++
Copyright (c) 2000  Microsoft Corporation

Module Name:
    nuiouser.h

Abstract:
    Constants and types to access the NDISPROT driver.
    Users must also include ntddndis.h

Environment:
    User/Kernel mode.
--*/

#ifndef __NPROTUSER__H
#define __NPROTUSER__H


#define FSCTL_BASE      FILE_DEVICE_NETWORK

#define _CTL_CODE(_Function, _Method, _Access)  CTL_CODE(FSCTL_BASE, _Function, _Method, _Access)

#define IOCTL_OPEN_DEVICE             _CTL_CODE(0x200, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)
#define IOCTL_QUERY_OID_VALUE         _CTL_CODE(0x201, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)
#define IOCTL_SET_OID_VALUE           _CTL_CODE(0x205, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)
#define IOCTL_QUERY_BINDING           _CTL_CODE(0x203, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)
#define IOCTL_BIND_WAIT               _CTL_CODE(0x204, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)


//  Structure to go with IOCTL_QUERY_OID_VALUE.
//  The Data part is of variable length, determined by the input buffer length passed to DeviceIoControl.
typedef struct _QUERY_OID {
    NDIS_OID            Oid;
    NDIS_PORT_NUMBER    PortNumber;
    UCHAR               Data[sizeof(ULONG)];
} QUERY_OID, * PQUERY_OID;


//  Structure to go with IOCTL_SET_OID_VALUE.
//  The Data part is of variable length, determined by the input buffer length passed to DeviceIoControl.
typedef struct _SET_OID {
    NDIS_OID            Oid;
    NDIS_PORT_NUMBER    PortNumber;
    UCHAR               Data[sizeof(ULONG)];
} SET_OID, * PSET_OID;


//  Structure to go with IOCTL_QUERY_BINDING.
//  The input parameter is BindingIndex, which is the index into the list of bindings active at the driver.
//  On successful completion, we get back a device name and a device descriptor (friendly name).
typedef struct _QUERY_BINDING {
    ULONG BindingIndex;      // 0-based binding number
    ULONG DeviceNameOffset;  // from start of this struct
    ULONG DeviceNameLength;  // in bytes
    ULONG DeviceDescrOffset; // from start of this struct
    ULONG DeviceDescrLength; // in bytes
} QUERY_BINDING, * PQUERY_BINDING;

#endif // __NPROTUSER__H
