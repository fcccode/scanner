/*++
Copyright (c) 2000  Microsoft Corporation

Module Name:
    debug.h

Abstract:
    Debug macros for NDISPROT
--*/

#pragma once

// Message verbosity: lower values indicate higher urgency
#define DL_EXTRA_LOUD       20
#define DL_VERY_LOUD        10
#define DL_LOUD             8
#define DL_INFO             6
#define DL_WARN             4
#define DL_ERROR            2
#define DL_FATAL            0

#define __FILENAME__ (strrchr(__FILE__, '\\') ? strrchr(__FILE__, '\\') + 1 : __FILE__)

#if DBG_SPIN_LOCK
typedef struct _NPROT_LOCK {
    ULONG          Signature;
    ULONG          IsAcquired;
    PKTHREAD       OwnerThread;
    ULONG          TouchedByFileNumber;
    ULONG          TouchedInLineNumber;
    NDIS_SPIN_LOCK NdisLock;
} NPROT_LOCK, * PNPROT_LOCK;

#define NPROTL_SIG    'KCOL'

extern NDIS_SPIN_LOCK       g_DbgLogLock;

extern VOID AllocateSpinLock(IN  PNPROT_LOCK pLock, IN  ULONG FileNumber, IN  ULONG LineNumber);
extern VOID FreeSpinLock(IN  PNPROT_LOCK pLock, IN  ULONG FileNumber, IN  ULONG LineNumber);
extern VOID AcquireSpinLock(IN  PNPROT_LOCK pLock, IN  BOOLEAN DispatchLevel, IN  ULONG FileNumber, IN  ULONG LineNumber);
extern VOID ReleaseSpinLock(IN  PNPROT_LOCK pLock, IN  BOOLEAN DispatchLevel, IN  ULONG FileNumber, IN  ULONG LineNumber);
extern VOID FreeDbgLock(VOID);

#define CHECK_LOCK_COUNT(Count)                                         \
            {                                                           \
                if ((INT)(Count) < 0)                                   \
                {                                                       \
                    DbgPrint("Lock Count %d is < 0! File %s, Line %d\n", Count, __FILENAME__, __LINE__);\
                    DbgBreakPoint();                                    \
                }                                                       \
            }
#else
#define CHECK_LOCK_COUNT(Count)
typedef NDIS_SPIN_LOCK      NPROT_LOCK;
typedef PNDIS_SPIN_LOCK     PNPROT_LOCK;
#endif


#if DBG

extern INT                g_DebugLevel;

#define DEBUGP(lev, stmt)                                               \
        {                                                               \
            if ((lev) <= g_DebugLevel)                             \
            {                                                           \
                DbgPrint("Ndisprot: FILE:%s, LINE:%d, ", __FILENAME__, __LINE__); DbgPrint stmt;\
            }                                                           \
        }

#define DEBUGPDUMP(lev, pBuf, Len)                                      \
        {                                                               \
            if ((lev) <= g_DebugLevel)                             \
            {                                                           \
                DbgPrintHexDump((PUCHAR)(pBuf), (ULONG)(Len));          \
            }                                                           \
        }

#define NPROT_ASSERT(exp)                                                \
        {                                                               \
            if (!(exp))                                                 \
            {                                                           \
                DbgPrint("Ndisprot: assert " #exp " failed in file %s, line %d\n", __FILENAME__, __LINE__);\
                DbgBreakPoint();                                        \
            }                                                           \
        }

#define NPROT_SET_SIGNATURE(s, t)        (s)->t##_sig = t##_signature;

#define NPROT_STRUCT_ASSERT(s, t)                                        \
        if ((s)->t##_sig != t##_signature)                              \
        {                                                               \
            DbgPrint("ndisprot: assertion failure for type " #t " at 0x%p in file %s, line %d\n", s, __FILENAME__, __LINE__);\
            DbgBreakPoint();                                            \
        }

// Memory Allocation/Freeing Audit:

// The NPROTD_ALLOCATION structure stores all info about one allocation
typedef struct _NPROTD_ALLOCATION {
    ULONG                    Signature;
    struct _NPROTD_ALLOCATION * Next;
    struct _NPROTD_ALLOCATION * Prev;
    ULONG                    FileNumber;
    ULONG                    LineNumber;
    ULONG                    Size;
    ULONG_PTR                Location;  // where the returned ptr was stored
    union
    {
        ULONGLONG            Alignment;
        UCHAR                UserData;
    };
} NPROTD_ALLOCATION, * PNPROTD_ALLOCATION;

#define NPROTD_MEMORY_SIGNATURE    (ULONG)'CSII'

extern PVOID AuditAllocMem(PVOID pPointer, ULONG Size, ULONG FileNumber, ULONG LineNumber);
extern VOID AuditFreeMem(PVOID Pointer);
extern VOID AuditShutdown(VOID);
extern VOID DbgPrintHexDump(PUCHAR pBuffer, ULONG Length);

#else
#define DEBUGP(lev, stmt)
#define DEBUGPDUMP(lev, pBuf, Len)

#define NPROT_ASSERT(exp)
#define NPROT_SET_SIGNATURE(s, t) UNREFERENCED_PARAMETER(s)
#define NPROT_STRUCT_ASSERT(s, t) UNREFERENCED_PARAMETER(s)
#endif
