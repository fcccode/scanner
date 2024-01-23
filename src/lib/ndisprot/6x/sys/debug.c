/*++
Copyright (c) 1997  Microsoft Corporation

Module Name:
    debug.c

Abstract:
    This module contains all debug-related code.
--*/

#include <precomp.h>

#define __FILENUMBER 'GBED'


#if DBG

INT             	g_DebugLevel = DL_WARN;//DL_WARN DL_EXTRA_LOUD
NDIS_SPIN_LOCK		g_DbgLogLock;

PNPROTD_ALLOCATION	g_MemoryHead = (PNPROTD_ALLOCATION)NULL;
PNPROTD_ALLOCATION	g_MemoryTail = (PNPROTD_ALLOCATION)NULL;
ULONG				g_AllocCount = 0;	// how many allocated so far (unfreed)

NDIS_SPIN_LOCK		g_MemoryLock;
BOOLEAN				g_InitDone = FALSE;


PVOID AuditAllocMem(PVOID	pPointer, ULONG	Size, ULONG	FileNumber, ULONG	LineNumber)
{
    PVOID				pBuffer;
    PNPROTD_ALLOCATION	pAllocInfo;

    if (!g_InitDone) {
        NdisAllocateSpinLock(&(g_MemoryLock));
        g_InitDone = TRUE;
    }

    NdisAllocateMemoryWithTag((PVOID *)&pAllocInfo, Size + sizeof(NPROTD_ALLOCATION), (ULONG)'oiuN');
    if (pAllocInfo == (PNPROTD_ALLOCATION)NULL) {
        DEBUGP(DL_VERY_LOUD + 50, ("AuditAllocMem: file %d, line %d, Size %d failed!\n", FileNumber, LineNumber, Size));
        pBuffer = NULL;
    } else {
        pBuffer = (PVOID) & (pAllocInfo->UserData);
        NPROT_SET_MEM(pBuffer, 0xaf, Size);
        pAllocInfo->Signature = NPROTD_MEMORY_SIGNATURE;
        pAllocInfo->FileNumber = FileNumber;
        pAllocInfo->LineNumber = LineNumber;
        pAllocInfo->Size = Size;
        pAllocInfo->Location = (ULONG_PTR)pPointer;
        pAllocInfo->Next = (PNPROTD_ALLOCATION)NULL;

        NdisAcquireSpinLock(&(g_MemoryLock));

        pAllocInfo->Prev = g_MemoryTail;
        if (g_MemoryTail == (PNPROTD_ALLOCATION)NULL) {
            // empty list
            g_MemoryHead = g_MemoryTail = pAllocInfo;
        } else {
            g_MemoryTail->Next = pAllocInfo;
        }
        g_MemoryTail = pAllocInfo;

        g_AllocCount++;
        NdisReleaseSpinLock(&(g_MemoryLock));
    }

    DEBUGP(DL_VERY_LOUD + 100,
           ("AuditAllocMem: file %c%c%c%c, line %d, %d bytes, [0x%p] <- 0x%p\n",
            (CHAR)(FileNumber & 0xff),
            (CHAR)((FileNumber >> 8) & 0xff),
            (CHAR)((FileNumber >> 16) & 0xff),
            (CHAR)((FileNumber >> 24) & 0xff),
            LineNumber, Size, pPointer, pBuffer));

    return (pBuffer);
}


VOID AuditFreeMem(PVOID	Pointer)
{
    PNPROTD_ALLOCATION	pAllocInfo;

    NdisAcquireSpinLock(&(g_MemoryLock));

    pAllocInfo = CONTAINING_RECORD(Pointer, NPROTD_ALLOCATION, UserData);

    if (pAllocInfo->Signature != NPROTD_MEMORY_SIGNATURE) {
        DEBUGP(DL_ERROR, ("AuditFreeMem: unknown buffer 0x%p!\n", Pointer));
        NdisReleaseSpinLock(&(g_MemoryLock));
#if DBG
        DbgBreakPoint();
#endif
        return;
    }

    pAllocInfo->Signature = (ULONG)'DEAD';
    if (pAllocInfo->Prev != (PNPROTD_ALLOCATION)NULL) {
        pAllocInfo->Prev->Next = pAllocInfo->Next;
    } else {
        g_MemoryHead = pAllocInfo->Next;
    }

    if (pAllocInfo->Next != (PNPROTD_ALLOCATION)NULL) {
        pAllocInfo->Next->Prev = pAllocInfo->Prev;
    } else {
        g_MemoryTail = pAllocInfo->Prev;
    }

    g_AllocCount--;
    NdisReleaseSpinLock(&(g_MemoryLock));

    NdisFreeMemory(pAllocInfo, 0, 0);
}


VOID AuditShutdown(VOID)
{
    if (g_InitDone) {
        if (g_AllocCount != 0) {
            DEBUGP(DL_ERROR, ("AuditShutdown: unfreed memory, %d blocks!\n", g_AllocCount));
            DEBUGP(DL_ERROR, ("MemoryHead: 0x%p, MemoryTail: 0x%p\n", g_MemoryHead, g_MemoryTail));
            DbgBreakPoint();

            {
                PNPROTD_ALLOCATION		pAllocInfo;

                while (g_MemoryHead != (PNPROTD_ALLOCATION)NULL) {
                    pAllocInfo = g_MemoryHead;
                    DEBUGP(DL_INFO, ("AuditShutdown: will free 0x%p\n", pAllocInfo));
                    AuditFreeMem(&(pAllocInfo->UserData));
                }
            }
        }

        g_InitDone = FALSE;
    }
}


#define MAX_HD_LENGTH		128


VOID DbgPrintHexDump(IN	PUCHAR pBuffer, IN	ULONG Length)
/*++
Routine Description:
    Print a hex dump of the given contiguous buffer.
    If the length is too long, we truncate it.
Arguments:
    pBuffer			- Points to start of data to be dumped
    Length			- Length of above.
--*/
{
    ULONG		i;

    if (Length > MAX_HD_LENGTH) {
        Length = MAX_HD_LENGTH;
    }

    for (i = 0; i < Length; i++) {
        //  Check if we are at the end of a line
        if ((i > 0) && ((i & 0xf) == 0)) {
            DbgPrint("\n");
        }

        //  Print addr if we are at start of a new line
        if ((i & 0xf) == 0) {
            DbgPrint("%08p ", pBuffer);
        }

        DbgPrint(" %02x", *pBuffer++);
    }

    //  Terminate the last line.
    if (Length > 0) {
        DbgPrint("\n");
    }
}


#endif // DBG


#if DBG_SPIN_LOCK
ULONG	g_SpinLockInitDone = 0;
NDIS_SPIN_LOCK	g_LockLock;


VOID AllocateSpinLock(IN	PNPROT_LOCK pLock, IN	ULONG FileNumber, IN	ULONG LineNumber)
{
    if (g_SpinLockInitDone == 0) {
        g_SpinLockInitDone = 1;
        NdisAllocateSpinLock(&(g_LockLock));
    }

    NdisAcquireSpinLock(&(g_LockLock));
    pLock->Signature = NPROTL_SIG;
    pLock->TouchedByFileNumber = FileNumber;
    pLock->TouchedInLineNumber = LineNumber;
    pLock->IsAcquired = 0;
    pLock->OwnerThread = 0;
    NdisAllocateSpinLock(&(pLock->NdisLock));
    NdisReleaseSpinLock(&(g_LockLock));
}


VOID FreeSpinLock(IN    PNPROT_LOCK pLock, IN    ULONG FileNumber, IN    ULONG LineNumber)
{
    NdisAcquireSpinLock(&(g_LockLock));
    pLock->Signature = NUIOL_SIG;
    pLock->TouchedByFileNumber = FileNumber;
    pLock->TouchedInLineNumber = LineNumber;
    pLock->IsAcquired = 0;
    pLock->OwnerThread = 0;
    NdisFreeSpinLock(&(pLock->NdisLock));
    NdisReleaseSpinLock(&(g_LockLock));
}


VOID FreeDbgLock(VOID)
{
    ASSERT(g_SpinLockInitDone == 1);

    g_SpinLockInitDone = 0;
    NdisFreeSpinLock(&(g_LockLock));
}


VOID AcquireSpinLock(IN	PNPROT_LOCK pLock, IN BOOLEAN DispatchLevel, IN	ULONG FileNumber, IN ULONG LineNumber)
{
    PKTHREAD		pThread;

    pThread = KeGetCurrentThread();
    if (DispatchLevel == TRUE) {
        NdisDprAcquireSpinLock(&(g_LockLock));
    } else {
        NdisAcquireSpinLock(&(g_LockLock));
    }

    if (pLock->Signature != NPROTL_SIG) {
        DbgPrint("Trying to acquire uninited lock 0x%x, File %c%c%c%c, Line %d\n",
                 pLock,
                 (CHAR)(FileNumber & 0xff),
                 (CHAR)((FileNumber >> 8) & 0xff),
                 (CHAR)((FileNumber >> 16) & 0xff),
                 (CHAR)((FileNumber >> 24) & 0xff),
                 LineNumber);
        DbgBreakPoint();
    }

    if (pLock->IsAcquired != 0) {
        if (pLock->OwnerThread == pThread) {
            DbgPrint("Detected multiple locking!: pLock 0x%x, File %c%c%c%c, Line %d\n",
                     pLock,
                     (CHAR)(FileNumber & 0xff),
                     (CHAR)((FileNumber >> 8) & 0xff),
                     (CHAR)((FileNumber >> 16) & 0xff),
                     (CHAR)((FileNumber >> 24) & 0xff),
                     LineNumber);
            DbgPrint("pLock 0x%x already acquired in File %c%c%c%c, Line %d\n",
                     pLock,
                     (CHAR)(pLock->TouchedByFileNumber & 0xff),
                     (CHAR)((pLock->TouchedByFileNumber >> 8) & 0xff),
                     (CHAR)((pLock->TouchedByFileNumber >> 16) & 0xff),
                     (CHAR)((pLock->TouchedByFileNumber >> 24) & 0xff),
                     pLock->TouchedInLineNumber);
            DbgBreakPoint();
        }
    }

    pLock->IsAcquired++;
    if (DispatchLevel == TRUE) {
        NdisDprReleaseSpinLock(&(g_LockLock));
        NdisDprAcquireSpinLock(&(pLock->NdisLock));
    } else {
        NdisReleaseSpinLock(&(g_LockLock));
        NdisAcquireSpinLock(&(pLock->NdisLock));
    }

    //  Mark this lock.
    pLock->OwnerThread = pThread;
    pLock->TouchedByFileNumber = FileNumber;
    pLock->TouchedInLineNumber = LineNumber;
}


VOID ReleaseSpinLock(IN	PNPROT_LOCK pLock,
                     IN  BOOLEAN DispatchLevel,
                     IN	ULONG FileNumber,
                     IN	ULONG LineNumber)
{
    NdisDprAcquireSpinLock(&(g_LockLock));
    if (pLock->Signature != NPROTL_SIG) {
        DbgPrint("Trying to release uninited lock 0x%x, File %c%c%c%c, Line %d\n",
                 pLock,
                 (CHAR)(FileNumber & 0xff),
                 (CHAR)((FileNumber >> 8) & 0xff),
                 (CHAR)((FileNumber >> 16) & 0xff),
                 (CHAR)((FileNumber >> 24) & 0xff),
                 LineNumber);
        DbgBreakPoint();
    }

    if (pLock->IsAcquired == 0) {
        DbgPrint("Detected release of unacquired lock 0x%x, File %c%c%c%c, Line %d\n",
                 pLock,
                 (CHAR)(FileNumber & 0xff),
                 (CHAR)((FileNumber >> 8) & 0xff),
                 (CHAR)((FileNumber >> 16) & 0xff),
                 (CHAR)((FileNumber >> 24) & 0xff),
                 LineNumber);
        DbgBreakPoint();
    }

    pLock->TouchedByFileNumber = FileNumber;
    pLock->TouchedInLineNumber = LineNumber;
    pLock->IsAcquired--;
    pLock->OwnerThread = 0;
    NdisDprReleaseSpinLock(&(g_LockLock));
    if (DispatchLevel == TRUE) {
        NdisDprReleaseSpinLock(&(pLock->NdisLock));
    } else {
        NdisReleaseSpinLock(&(pLock->NdisLock));
    }
}

#endif // DBG_SPIN_LOCK
