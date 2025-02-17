/*++
Copyright (c) 2000  Microsoft Corporation

Module Name:
    ndisbind.c

Abstract:
    NDIS protocol entry points and utility routines to handle binding and unbinding from adapters.

Environment:
    Kernel mode only.
--*/


#include "precomp.h"

#define __FILENUMBER 'DNIB'

NDIS_OID    g_SupportedSetOids[] = {
    OID_802_11_INFRASTRUCTURE_MODE,
    OID_802_11_AUTHENTICATION_MODE,
    OID_802_11_RELOAD_DEFAULTS,
    OID_802_11_REMOVE_WEP,
    OID_802_11_WEP_STATUS,
    OID_802_11_BSSID_LIST_SCAN,
    OID_802_11_ADD_WEP,
    OID_802_11_SSID,
    OID_802_11_BSSID,
    OID_802_11_BSSID_LIST,
    OID_802_11_DISASSOCIATE,
    OID_802_11_STATISTICS,            // Later used by power management
    OID_802_11_POWER_MODE,            // Later  used by power management
    OID_802_11_NETWORK_TYPE_IN_USE,
    OID_802_11_RSSI,
    OID_802_11_SUPPORTED_RATES,
    OID_802_11_CONFIGURATION,
    OID_802_3_MULTICAST_LIST,
};


NDIS_STATUS BindAdapter(IN NDIS_HANDLE ProtocolDriverContext,
                        IN NDIS_HANDLE BindContext,
                        IN PNDIS_BIND_PARAMETERS BindParameters
)
/*++
Routine Description:
    Protocol Bind Handler entry point called when NDIS wants us to bind to an adapter.
    We go ahead and set up a binding.
    An OPEN_CONTEXT structure is allocated to keep state about this binding.
Return Value:
    None
--*/
{
    POPEN_CONTEXT pOpenContext;
    NDIS_STATUS   Status;

    UNREFERENCED_PARAMETER(ProtocolDriverContext);

    do {
        //  Allocate our context for this open.
        NPROT_ALLOC_MEM(pOpenContext, sizeof(OPEN_CONTEXT));
        if (pOpenContext == NULL) {
            Status = NDIS_STATUS_RESOURCES;
            break;
        }

        //  Initialize it.
        NPROT_ZERO_MEM(pOpenContext, sizeof(OPEN_CONTEXT));
        NPROT_SET_SIGNATURE(pOpenContext, oc);

        NPROT_INIT_LOCK(&pOpenContext->Lock);
        NPROT_INIT_LIST_HEAD(&pOpenContext->PendedReads);
        NPROT_INIT_LIST_HEAD(&pOpenContext->PendedWrites);
        NPROT_INIT_LIST_HEAD(&pOpenContext->RecvNetBufListQueue);
        NPROT_INIT_EVENT(&pOpenContext->PoweredUpEvent);

        //  Start off by assuming that the device below is powered up.
        NPROT_SIGNAL_EVENT(&pOpenContext->PoweredUpEvent);

        NPROT_REF_OPEN(pOpenContext); // Bind

        //  Add it to the global list.
        NPROT_ACQUIRE_LOCK(&Globals.GlobalLock, FALSE);
        NPROT_INSERT_TAIL_LIST(&Globals.OpenList, &pOpenContext->Link);
        NPROT_RELEASE_LOCK(&Globals.GlobalLock, FALSE);

        pOpenContext->State = Initializing;

        // Here we reference the open context to make sure that even if 
        // CreateBinding failed, open context is still valid
        NPROT_REF_OPEN(pOpenContext);

        //  Set up the NDIS binding, CreateBinding does the cleanup for the 
        //  binding if somehow it fails to create the binding, the
        Status = CreateBinding(pOpenContext,
                               BindParameters,
                               BindContext,
                               (PUCHAR)BindParameters->AdapterName->Buffer,
                               BindParameters->AdapterName->Length);
        if (Status != NDIS_STATUS_SUCCESS) {
            // Dereference the open context because we referenced it before we call CreateBinding
            NPROT_DEREF_OPEN(pOpenContext);
            break;
        }

        // Dereference the open context because we referenced it before we call CreateBinding
        NPROT_DEREF_OPEN(pOpenContext);
    } while (FALSE);

    return Status;
}


VOID OpenAdapterComplete(IN NDIS_HANDLE ProtocolBindingContext, IN NDIS_STATUS Status)
/*++
Routine Description:
    Completion routine called by NDIS if our call to NdisOpenAdapterEx pends.
    Wake up the thread that called NdisOpenAdapterEx.
Arguments:
    ProtocolBindingContext - pointer to open context structure
    Status - status of the open
--*/
{
    POPEN_CONTEXT pOpenContext = (POPEN_CONTEXT)ProtocolBindingContext;

    NPROT_STRUCT_ASSERT(pOpenContext, oc);

    pOpenContext->BindStatus = Status;

    NPROT_SIGNAL_EVENT(&pOpenContext->BindEvent);
}


NDIS_STATUS UnbindAdapter(IN NDIS_HANDLE UnbindContext, IN NDIS_HANDLE ProtocolBindingContext)
/*++
Routine Description:
    NDIS calls this when it wants us to close the binding to an adapter.
Arguments:
    ProtocolBindingContext - pointer to open context structure
    UnbindContext - to use in NdisCompleteUnbindAdapter if we return pending
Return Value:
    pending or success
--*/
{
    POPEN_CONTEXT pOpenContext = (POPEN_CONTEXT)ProtocolBindingContext;

    UNREFERENCED_PARAMETER(UnbindContext);

    NPROT_STRUCT_ASSERT(pOpenContext, oc);

    NPROT_ACQUIRE_LOCK(&pOpenContext->Lock, FALSE);//  Mark this open as having seen an Unbind.

    NPROT_SET_FLAGS(pOpenContext->Flags, NPROTO_UNBIND_FLAGS, NPROTO_UNBIND_RECEIVED);

    //  In case we had threads blocked for the device below to be powered up, wake them up.
    NPROT_SIGNAL_EVENT(&pOpenContext->PoweredUpEvent);

    NPROT_RELEASE_LOCK(&pOpenContext->Lock, FALSE);

    pOpenContext->State = Closing;

    ShutdownBinding(pOpenContext);

    return NDIS_STATUS_SUCCESS;
}


VOID CloseAdapterComplete(IN NDIS_HANDLE ProtocolBindingContext)
/*++
Routine Description:
    Called by NDIS to complete a pended call to NdisCloseAdapter.
    We wake up the thread waiting for this completion.
Arguments:
    ProtocolBindingContext - pointer to open context structure
--*/
{
    POPEN_CONTEXT pOpenContext = (POPEN_CONTEXT)ProtocolBindingContext;

    NPROT_STRUCT_ASSERT(pOpenContext, oc);

    NPROT_SIGNAL_EVENT(&pOpenContext->BindEvent);
}


NDIS_STATUS PnPEventHandler(IN NDIS_HANDLE ProtocolBindingContext,
                            IN PNET_PNP_EVENT_NOTIFICATION  pNetPnPEventNotification
)
/*++
Routine Description:
    Called by NDIS to notify us of a PNP event. The most significant one for us is power state change.
Arguments:
    ProtocolBindingContext - pointer to open context structure this is NULL for global reconfig events.
    pNetPnPEventNotification - pointer to the PNP event notification
Return Value:
    Our processing status for the PNP event.
--*/
{
    POPEN_CONTEXT pOpenContext = (POPEN_CONTEXT)ProtocolBindingContext;
    NDIS_STATUS   Status = NDIS_STATUS_SUCCESS;
    PUCHAR        Buffer = NULL;
    ULONG         BufferLength = 0;
    PNDIS_PROTOCOL_RESTART_PARAMETERS RestartParameters = NULL;

    switch (pNetPnPEventNotification->NetPnPEvent.NetEvent) {
    case NetEventSetPower:
        NPROT_STRUCT_ASSERT(pOpenContext, oc);
        pOpenContext->PowerState = *(PNET_DEVICE_POWER_STATE)pNetPnPEventNotification->NetPnPEvent.Buffer;

        if (pOpenContext->PowerState > NetDeviceStateD0) {
            //  The device below is transitioning to a low power state.
            //  Block any threads attempting to query the device while in this state.
            NPROT_INIT_EVENT(&pOpenContext->PoweredUpEvent);

            // There is no need to wait for pending I/O here.
            // We wait for it in the NetEventPause handler.

            FlushReceiveQueue(pOpenContext);//  Return any receives that we had queued up.
            DEBUGP(DL_INFO, ("PnPEvent: Open %p, SetPower to %d\n", pOpenContext, pOpenContext->PowerState));
        } else {//  The device below is powered up.
            DEBUGP(DL_INFO, ("PnPEvent: Open %p, SetPower ON: %d\n", pOpenContext, pOpenContext->PowerState));
            NPROT_SIGNAL_EVENT(&pOpenContext->PoweredUpEvent);
        }

        Status = NDIS_STATUS_SUCCESS;
        break;
    case NetEventQueryPower:
        Status = NDIS_STATUS_SUCCESS;
        break;
    case NetEventBindsComplete:
        NPROT_SIGNAL_EVENT(&Globals.BindsComplete);
        Status = NDIS_STATUS_SUCCESS;
        break;
    case NetEventPause:
        // Wait all sends to be complete.
        NPROT_ACQUIRE_LOCK(&pOpenContext->Lock, FALSE);
        pOpenContext->State = Pausing;

        // we could also complete the PnP Event asynchrously.
        while (TRUE) {
            if (pOpenContext->PendedSendCount == 0)
                break;

            NPROT_RELEASE_LOCK(&pOpenContext->Lock, FALSE);
            DEBUGP(DL_INFO, ("PnPEvent: Open %p, outstanding count is %d\n", pOpenContext, pOpenContext->PendedSendCount));

            NdisMSleep(100000);    // 100 ms.

            NPROT_ACQUIRE_LOCK(&pOpenContext->Lock, FALSE);
        }

        NPROT_RELEASE_LOCK(&pOpenContext->Lock, FALSE);

        // Return all queued receives.
        FlushReceiveQueue(pOpenContext);
        pOpenContext->State = Paused;
        break;
    case NetEventRestart:
        ASSERT(pOpenContext->State == Paused);

        // Get the updated attributes
        Buffer = pNetPnPEventNotification->NetPnPEvent.Buffer;
        if (Buffer == NULL) {
            pOpenContext->State = Running;
            break;
        }
        BufferLength = pNetPnPEventNotification->NetPnPEvent.BufferLength;

        ASSERT(BufferLength == sizeof(NDIS_PROTOCOL_RESTART_PARAMETERS));

        RestartParameters = (PNDIS_PROTOCOL_RESTART_PARAMETERS)Buffer;
        Restart(pOpenContext, RestartParameters);

        pOpenContext->State = Running;
        break;
    case NetEventQueryRemoveDevice:
    case NetEventCancelRemoveDevice:
    case NetEventReconfigure:
    case NetEventBindList:
    case NetEventPnPCapabilities:
        Status = NDIS_STATUS_SUCCESS;
        break;
    default:
        Status = NDIS_STATUS_NOT_SUPPORTED;
        break;
    }

    DEBUGP(DL_INFO, ("PnPEvent: Open %p, Event %d, Status %x\n",
                     pOpenContext, pNetPnPEventNotification->NetPnPEvent.NetEvent, Status));

    return (Status);
}


VOID ProtocolUnloadHandler(VOID)
/*++
Routine Description:
    NDIS calls this on a usermode request to uninstall us.
--*/
{
    DoProtocolUnload();
}


NDIS_STATUS CreateBinding(IN POPEN_CONTEXT pOpenContext,
                          IN PNDIS_BIND_PARAMETERS BindParameters,
                          IN NDIS_HANDLE BindContext,
                          _In_reads_bytes_(BindingInfoLength) IN PUCHAR pBindingInfo,
                          IN ULONG BindingInfoLength
)
/*++
Routine Description:
    Utility function to create an NDIS binding to the indicated device, if no such binding exists.
    Here is where we also allocate additional resources (e.g. packet pool) for the binding.
    NOTE: this function blocks and finishes synchronously.
Arguments:
    pOpenContext - pointer to open context block
    BindParameters - pointer to NDIS_BIND_PARAMETERS
    BindConext - pointer to NDIS bind context
    pBindingInfo - pointer to unicode device name string
    BindingInfoLength - length in bytes of the above.
Return Value:
    NDIS_STATUS_SUCCESS if a binding was successfully set up.
    NDIS_STATUS_XXX error code on any failure.
--*/
{
    NDIS_STATUS              Status = NDIS_STATUS_SUCCESS;
    NDIS_MEDIUM              MediumArray[1] = {NdisMedium802_3};
    NDIS_OPEN_PARAMETERS     OpenParameters;
    NET_BUFFER_LIST_POOL_PARAMETERS PoolParameters;
    UINT                     SelectedMediumIndex;
    BOOLEAN                  fOpenComplete = FALSE;
    ULONG                    GenericUlong = 0;
    NET_FRAME_TYPE           FrameTypeArray[2] = {NDIS_ETH_TYPE_802_1X, NDIS_ETH_TYPE_802_1Q};
#if DBG
    POPEN_CONTEXT   pTmpOpenContext;
#endif    

    DEBUGP(DL_LOUD, ("CreateBinding: open %p/%x, device [%s]\n", pOpenContext, pOpenContext->Flags, pBindingInfo));

    do {
        //  Check if we already have a binding to this device.
#if DBG        
        pTmpOpenContext = LookupDevice(pBindingInfo, BindingInfoLength);
        ASSERT(pTmpOpenContext == NULL);
        if (pTmpOpenContext != NULL) {
            DEBUGP(DL_WARN, ("CreateBinding: Binding to device %ws already exists on open %p\n", pTmpOpenContext->DeviceName.Buffer, pTmpOpenContext));
            NPROT_DEREF_OPEN(pTmpOpenContext);  // temp ref added by Lookup
            Status = NDIS_STATUS_FAILURE;
            break;
        }
#endif        

        NPROT_ACQUIRE_LOCK(&pOpenContext->Lock, FALSE);
        NPROT_SET_FLAGS(pOpenContext->Flags, NPROTO_BIND_FLAGS, NPROTO_BIND_OPENING);
        NPROT_RELEASE_LOCK(&pOpenContext->Lock, FALSE);

        //  Copy in the device name. Add room for a NULL terminator.
        NPROT_ALLOC_MEM(pOpenContext->DeviceName.Buffer, BindingInfoLength + sizeof(WCHAR));
        if (pOpenContext->DeviceName.Buffer == NULL) {
            DEBUGP(DL_WARN, ("CreateBinding: failed to alloc device name buf (%d bytes)\n", BindingInfoLength + sizeof(WCHAR)));
            Status = NDIS_STATUS_RESOURCES;
            break;
        }

        NPROT_COPY_MEM(pOpenContext->DeviceName.Buffer, pBindingInfo, BindingInfoLength);
#pragma prefast(suppress: 12009, "DeviceName length will not cause overflow")                                   
        * (PWCHAR)((PUCHAR)pOpenContext->DeviceName.Buffer + BindingInfoLength) = L'\0';
        NdisInitUnicodeString(&pOpenContext->DeviceName, pOpenContext->DeviceName.Buffer);

        NdisZeroMemory(&PoolParameters, sizeof(NET_BUFFER_LIST_POOL_PARAMETERS));

        PoolParameters.Header.Type = NDIS_OBJECT_TYPE_DEFAULT;
        PoolParameters.Header.Revision = NET_BUFFER_LIST_POOL_PARAMETERS_REVISION_1;
        PoolParameters.Header.Size = sizeof(PoolParameters);
        PoolParameters.ProtocolId = NDIS_PROTOCOL_ID_IPX;
        PoolParameters.ContextSize = sizeof(NPROT_SEND_NETBUFLIST_RSVD);
        PoolParameters.fAllocateNetBuffer = TRUE;
        PoolParameters.PoolTag = NPROT_ALLOC_TAG;

        pOpenContext->SendNetBufferListPool = NdisAllocateNetBufferListPool(Globals.NdisProtocolHandle, &PoolParameters);
        if (pOpenContext->SendNetBufferListPool == NULL) {
            DEBUGP(DL_WARN, ("CreateBinding: failed to alloc send net buffer list pool\n"));
            Status = NDIS_STATUS_RESOURCES;
            break;
        }

        PoolParameters.ContextSize = 0;

        pOpenContext->RecvNetBufferListPool = NdisAllocateNetBufferListPool(Globals.NdisProtocolHandle, &PoolParameters);
        if (pOpenContext->RecvNetBufferListPool == NULL) {
            DEBUGP(DL_WARN, ("CreateBinding: failed to alloc recv net buffer list pool.\n"));
            Status = NDIS_STATUS_RESOURCES;
            break;
        }

        pOpenContext->PowerState = NetDeviceStateD0;//  Assume that the device is powered up.        
        NPROT_INIT_EVENT(&pOpenContext->BindEvent);//  Open the adapter.

        NPROT_ZERO_MEM(&OpenParameters, sizeof(NDIS_OPEN_PARAMETERS));
        OpenParameters.Header.Revision = NDIS_OPEN_PARAMETERS_REVISION_1;
        OpenParameters.Header.Size = sizeof(NDIS_OPEN_PARAMETERS);
        OpenParameters.Header.Type = NDIS_OBJECT_TYPE_OPEN_PARAMETERS;
        OpenParameters.AdapterName = BindParameters->AdapterName;
        OpenParameters.MediumArray = &MediumArray[0];
        OpenParameters.MediumArraySize = sizeof(MediumArray) / sizeof(NDIS_MEDIUM);
        OpenParameters.SelectedMediumIndex = &SelectedMediumIndex;
        OpenParameters.FrameTypeArray = &FrameTypeArray[0];
        OpenParameters.FrameTypeArraySize = sizeof(FrameTypeArray) / sizeof(NET_FRAME_TYPE);

        NDIS_DECLARE_PROTOCOL_OPEN_CONTEXT(OPEN_CONTEXT);
        Status = NdisOpenAdapterEx(Globals.NdisProtocolHandle,
                                   (NDIS_HANDLE)pOpenContext,
                                   &OpenParameters,
                                   BindContext,
                                   &pOpenContext->BindingHandle);
        if (Status == NDIS_STATUS_PENDING) {
            NPROT_WAIT_EVENT(&pOpenContext->BindEvent, 0);
            Status = pOpenContext->BindStatus;
        }

        if (Status != NDIS_STATUS_SUCCESS) {
            DEBUGP(DL_WARN, ("CreateBinding: NdisOpenAdapter (%ws) failed: %x\n", pOpenContext->DeviceName.Buffer, Status));
            break;
        }

        pOpenContext->State = Paused;

        fOpenComplete = TRUE;

        //  Get the friendly name for the adapter. It is not fatal for this to fail.
        (VOID)NdisQueryAdapterInstanceName(&pOpenContext->DeviceDescr, pOpenContext->BindingHandle);

        NdisMoveMemory(&pOpenContext->CurrentAddress[0], BindParameters->CurrentMacAddress, NPROT_MAC_ADDR_LEN);

        pOpenContext->MacOptions = BindParameters->MacOptions;//  Get MAC options.        
        pOpenContext->MaxFrameSize = BindParameters->MtuSize;//  Get the max frame size.        
        GenericUlong = BindParameters->MediaConnectState;//  Get the media connect status.

        if (GenericUlong == NdisMediaStateConnected) {
            NPROT_SET_FLAGS(pOpenContext->Flags, NPROTO_MEDIA_FLAGS, NPROTO_MEDIA_CONNECTED);
        } else {
            NPROT_SET_FLAGS(pOpenContext->Flags, NPROTO_MEDIA_FLAGS, NPROTO_MEDIA_DISCONNECTED);
        }

        // Get the back fill size
        pOpenContext->DataBackFillSize = BindParameters->DataBackFillSize;
        pOpenContext->ContextBackFillSize = BindParameters->ContextBackFillSize;

        //  Mark this open. Also check if we received an Unbind while we were setting this up.
        NPROT_ACQUIRE_LOCK(&pOpenContext->Lock, FALSE);
        NPROT_SET_FLAGS(pOpenContext->Flags, NPROTO_BIND_FLAGS, NPROTO_BIND_ACTIVE);
        ASSERT(!NPROT_TEST_FLAGS(pOpenContext->Flags, NPROTO_UNBIND_FLAGS, NPROTO_UNBIND_RECEIVED));
        NPROT_RELEASE_LOCK(&pOpenContext->Lock, FALSE);
    } while (FALSE);

    if (Status != NDIS_STATUS_SUCCESS) {
        NPROT_ACQUIRE_LOCK(&pOpenContext->Lock, FALSE);
        if (fOpenComplete) {//  Check if we had actually finished opening the adapter.
            NPROT_SET_FLAGS(pOpenContext->Flags, NPROTO_BIND_FLAGS, NPROTO_BIND_ACTIVE);
        } else if (NPROT_TEST_FLAGS(pOpenContext->Flags, NPROTO_BIND_FLAGS, NPROTO_BIND_OPENING)) {
            NPROT_SET_FLAGS(pOpenContext->Flags, NPROTO_BIND_FLAGS, NPROTO_BIND_FAILED);
        }
        NPROT_RELEASE_LOCK(&pOpenContext->Lock, FALSE);

        ShutdownBinding(pOpenContext);
    }

    DEBUGP(DL_INFO, ("CreateBinding: OpenContext %p, Status %x\n", pOpenContext, Status));

    return (Status);
}


VOID ShutdownBinding(IN POPEN_CONTEXT pOpenContext)
/*++
Routine Description:
    Utility function to shut down the NDIS binding, if one exists, on the specified open. This is written to be called from:
        CreateBinding - on failure
        UnbindAdapter

    We handle the case where a binding is in the process of being set up.
    This precaution is not needed if this routine is only called from the context of our UnbindAdapter handler,
    but they are here in case we initiate unbinding from elsewhere (e.g. on processing a user command).

    NOTE: this blocks and finishes synchronously.
Arguments:
    pOpenContext - pointer to open context block
--*/
{
    NDIS_STATUS Status;
    BOOLEAN     DoCloseBinding = FALSE;
    NPROT_EVENT ClosingEvent;

    do {
        NPROT_ACQUIRE_LOCK(&pOpenContext->Lock, FALSE);

        if (NPROT_TEST_FLAGS(pOpenContext->Flags, NPROTO_BIND_FLAGS, NPROTO_BIND_OPENING)) {
            //  We are still in the process of setting up this binding.
            NPROT_RELEASE_LOCK(&pOpenContext->Lock, FALSE);
            break;
        }

        if (NPROT_TEST_FLAGS(pOpenContext->Flags, NPROTO_BIND_FLAGS, NPROTO_BIND_ACTIVE)) {
            ASSERT(pOpenContext->ClosingEvent == NULL);
            pOpenContext->ClosingEvent = NULL;

            NPROT_SET_FLAGS(pOpenContext->Flags, NPROTO_BIND_FLAGS, NPROTO_BIND_CLOSING);

            if (pOpenContext->PendedSendCount != 0) {
                pOpenContext->ClosingEvent = &ClosingEvent;
                NPROT_INIT_EVENT(&ClosingEvent);
            }

            DoCloseBinding = TRUE;
        }

        NPROT_RELEASE_LOCK(&pOpenContext->Lock, FALSE);

        if (DoCloseBinding) {
            ULONG PacketFilter = 0;
            ULONG BytesRead = 0;

            // Set Packet filter to 0 before closing the binding
            Status = DoRequest(pOpenContext,
                               NDIS_DEFAULT_PORT_NUMBER,
                               NdisRequestSetInformation,
                               OID_GEN_CURRENT_PACKET_FILTER,
                               &PacketFilter,
                               sizeof(PacketFilter),
                               &BytesRead);
            if (Status != NDIS_STATUS_SUCCESS) {
                DEBUGP(DL_WARN, ("ShutDownBinding: set packet filter failed: %x\n", Status));
            }

            // Set multicast list to null before closing the binding
            Status = DoRequest(pOpenContext,
                               NDIS_DEFAULT_PORT_NUMBER,
                               NdisRequestSetInformation,
                               OID_802_3_MULTICAST_LIST,
                               NULL,
                               0,
                               &BytesRead);
            if (Status != NDIS_STATUS_SUCCESS) {
                DEBUGP(DL_WARN, ("ShutDownBinding: set multicast list failed: %x\n", Status));
            }

            WaitForPendingIO(pOpenContext, TRUE);//  Wait for any pending sends or requests on the binding to complete.            
            FlushReceiveQueue(pOpenContext);//  Discard any queued receives.            
            NPROT_INIT_EVENT(&pOpenContext->BindEvent);//  Close the binding now.

            DEBUGP(DL_INFO, ("ShutdownBinding: Closing OpenContext %p, BindingHandle %p\n", pOpenContext, pOpenContext->BindingHandle));

            Status = NdisCloseAdapterEx(pOpenContext->BindingHandle);
            if (Status == NDIS_STATUS_PENDING) {
                NPROT_WAIT_EVENT(&pOpenContext->BindEvent, 0);
                Status = pOpenContext->BindStatus;
            }
            NPROT_ASSERT(Status == NDIS_STATUS_SUCCESS);

            pOpenContext->BindingHandle = NULL;

            NPROT_ACQUIRE_LOCK(&pOpenContext->Lock, FALSE);
            NPROT_SET_FLAGS(pOpenContext->Flags, NPROTO_BIND_FLAGS, NPROTO_BIND_IDLE);
            NPROT_SET_FLAGS(pOpenContext->Flags, NPROTO_UNBIND_FLAGS, 0);
            NPROT_RELEASE_LOCK(&pOpenContext->Lock, FALSE);
        }
    } while (FALSE);

    //  Remove it from the global list.
    NPROT_ACQUIRE_LOCK(&Globals.GlobalLock, FALSE);
    NPROT_REMOVE_ENTRY_LIST(&pOpenContext->Link);
    NPROT_RELEASE_LOCK(&Globals.GlobalLock, FALSE);

    FreeBindResources(pOpenContext);//  Free any other resources allocated for this bind.

    NPROT_DEREF_OPEN(pOpenContext);  // Shutdown binding
}


VOID FreeBindResources(IN POPEN_CONTEXT pOpenContext)
/*++
Routine Description:
    Free any resources set up for an NDIS binding.
Arguments:
    pOpenContext - pointer to open context block
--*/
{
    if (pOpenContext->SendNetBufferListPool != NULL) {
        NdisFreeNetBufferListPool(pOpenContext->SendNetBufferListPool);
        pOpenContext->SendNetBufferListPool = NULL;
    }

    if (pOpenContext->RecvNetBufferListPool != NULL) {
        NdisFreeNetBufferListPool(pOpenContext->RecvNetBufferListPool);
        pOpenContext->RecvNetBufferListPool = NULL;
    }

    if (pOpenContext->DeviceName.Buffer != NULL) {
        NPROT_FREE_MEM(pOpenContext->DeviceName.Buffer);
        pOpenContext->DeviceName.Buffer = NULL;
        pOpenContext->DeviceName.Length =
            pOpenContext->DeviceName.MaximumLength = 0;
    }

    if (pOpenContext->DeviceDescr.Buffer != NULL) {
        // this would have been allocated by NdisQueryAdpaterInstanceName.
        NdisFreeMemory(pOpenContext->DeviceDescr.Buffer, 0, 0);
        pOpenContext->DeviceDescr.Buffer = NULL;
    }
}


VOID WaitForPendingIO(IN POPEN_CONTEXT pOpenContext, IN BOOLEAN DoCancelReads)
/*++
Routine Description:
    Utility function to wait for all outstanding I/O to complete on an open context.
    It is assumed that the open context won't go away while we are in this routine.
Arguments:
    pOpenContext - pointer to open context structure
    DoCancelReads - do we wait for pending reads to go away (and cancel them)?
--*/
{
    //  Wait for any pending sends or requests on the binding to complete.
    if (pOpenContext->PendedSendCount == 0) {
        ASSERT(pOpenContext->ClosingEvent == NULL);
    } else {
        ASSERT(pOpenContext->ClosingEvent != NULL);
        DEBUGP(DL_WARN, ("WaitForPendingIO: Open %p, %d pended sends\n", pOpenContext, pOpenContext->PendedSendCount));
        NPROT_WAIT_EVENT(pOpenContext->ClosingEvent, 0);
    }

    if (DoCancelReads) {
        //  Wait for any pended reads to complete/cancel.
        while (pOpenContext->PendedReadCount != 0) {
            DEBUGP(DL_INFO, ("WaitForPendingIO: Open %p, %d pended reads\n", pOpenContext, pOpenContext->PendedReadCount));
            CancelPendingReads(pOpenContext);//  Cancel any pending reads.
            NdisMSleep(100000);    // 100 ms.
        }
    }
}


VOID DoProtocolUnload(VOID)
/*++
Routine Description:
    Utility routine to handle unload from the NDIS protocol side.
--*/
{
    DEBUGP(DL_INFO, ("ProtocolUnload: ProtocolHandle %lp\n", Globals.NdisProtocolHandle));

    if (Globals.NdisProtocolHandle != NULL) {
        NDIS_HANDLE ProtocolHandle = Globals.NdisProtocolHandle;
        Globals.NdisProtocolHandle = NULL;
        NdisDeregisterProtocolDriver(ProtocolHandle);
    }
}


NDIS_STATUS DoRequest(IN POPEN_CONTEXT     pOpenContext,
                      IN NDIS_PORT_NUMBER  PortNumber,
                      IN NDIS_REQUEST_TYPE RequestType,
                      IN NDIS_OID          Oid,
                      IN PVOID             InformationBuffer,
                      IN ULONG             InformationBufferLength,
                      OUT PULONG           pBytesProcessed
)
/*++
Routine Description:
    Utility routine that forms and sends an NDIS_REQUEST to the miniport, waits for it to complete, and returns status to the caller.

    NOTE: this assumes that the calling routine ensures validity of the binding handle until this returns.
Arguments:
    pOpenContext - pointer to our open context
    PortNumber - the port to issue the request
    RequestType - NdisRequest[Set|Query|Method]Information
    Oid - the object being set/queried
    InformationBuffer - data for the request
    InformationBufferLength - length of the above
    pBytesProcessed - place to return bytes read/written
Return Value:
    Status of the set/query/method request
--*/
{
    REQUEST           ReqContext;
    PNDIS_OID_REQUEST pNdisRequest = &ReqContext.Request;
    NDIS_STATUS       Status;

    NdisZeroMemory(&ReqContext, sizeof(ReqContext));

    NPROT_INIT_EVENT(&ReqContext.ReqEvent);
    pNdisRequest->Header.Type = NDIS_OBJECT_TYPE_OID_REQUEST;
    pNdisRequest->Header.Revision = NDIS_OID_REQUEST_REVISION_1;
    pNdisRequest->Header.Size = sizeof(NDIS_OID_REQUEST);
    pNdisRequest->RequestType = RequestType;
    pNdisRequest->PortNumber = PortNumber;

    switch (RequestType) {
    case NdisRequestQueryInformation:
        pNdisRequest->DATA.QUERY_INFORMATION.Oid = Oid;
        pNdisRequest->DATA.QUERY_INFORMATION.InformationBuffer = InformationBuffer;
        pNdisRequest->DATA.QUERY_INFORMATION.InformationBufferLength = InformationBufferLength;
        break;
    case NdisRequestSetInformation:
        pNdisRequest->DATA.SET_INFORMATION.Oid = Oid;
        pNdisRequest->DATA.SET_INFORMATION.InformationBuffer = InformationBuffer;
        pNdisRequest->DATA.SET_INFORMATION.InformationBufferLength = InformationBufferLength;
        break;
    default:
        NPROT_ASSERT(FALSE);
        break;
    }

    pNdisRequest->RequestId = NPROT_GET_NEXT_CANCEL_ID();
    Status = NdisOidRequest(pOpenContext->BindingHandle, pNdisRequest);
    if (Status == NDIS_STATUS_PENDING) {
        NPROT_WAIT_EVENT(&ReqContext.ReqEvent, 0);
        Status = ReqContext.Status;
    }

    if (Status == NDIS_STATUS_SUCCESS) {
        *pBytesProcessed = (RequestType == NdisRequestQueryInformation) ?
            pNdisRequest->DATA.QUERY_INFORMATION.BytesWritten :
            pNdisRequest->DATA.SET_INFORMATION.BytesRead;

        // The driver below should set the correct value to BytesWritten or BytesRead. 
        // But now, we just truncate the value to InformationBufferLength
        if (*pBytesProcessed > InformationBufferLength) {
            *pBytesProcessed = InformationBufferLength;
        }
    }

    return (Status);
}


NDIS_STATUS ValidateOpenAndDoRequest(IN POPEN_CONTEXT     pOpenContext,
                                     IN NDIS_REQUEST_TYPE RequestType,
                                     IN NDIS_OID          Oid,
                                     IN PVOID             InformationBuffer,
                                     IN ULONG             InformationBufferLength,
                                     OUT PULONG           pBytesProcessed,
                                     IN BOOLEAN           bWaitForPowerOn
)
/*++
Routine Description:
    Utility routine to prevalidate and reference an open context before calling DoRequest.
    This routine makes sure we have a valid binding.
Arguments:
    pOpenContext - pointer to our open context
    RequestType - NdisRequest[Set|Query]Information
    Oid - the object being set/queried
    InformationBuffer - data for the request
    InformationBufferLength - length of the above
    pBytesProcessed - place to return bytes read/written
    bWaitForPowerOn - Wait for the device to be powered on if it isn't already.
Return Value:
    Status of the set/query request
--*/
{
    NDIS_STATUS Status;

    do {
        if (pOpenContext == NULL) {
            DEBUGP(DL_WARN, ("ValidateOpenAndDoRequest: request on unassociated file object!\n"));
            Status = NDIS_STATUS_INVALID_DATA;
            break;
        }

        NPROT_STRUCT_ASSERT(pOpenContext, oc);

        NPROT_ACQUIRE_LOCK(&pOpenContext->Lock, FALSE);

        //  Proceed only if we have a binding.
        if (!NPROT_TEST_FLAGS(pOpenContext->Flags, NPROTO_BIND_FLAGS, NPROTO_BIND_ACTIVE)) {
            NPROT_RELEASE_LOCK(&pOpenContext->Lock, FALSE);
            Status = NDIS_STATUS_INVALID_DATA;
            break;
        }

        NPROT_ASSERT(pOpenContext->BindingHandle != NULL);

        //  Make sure that the binding does not go away until we are finished with the request.
        pOpenContext->PendedSendCount++;

        NPROT_RELEASE_LOCK(&pOpenContext->Lock, FALSE);

        if (bWaitForPowerOn) {
            //  Wait for the device below to be powered up.
            //  We don't wait indefinitely here - this is to avoid a PROCESS_HAS_LOCKED_PAGES bugcheck that could happen
            //  if the calling process terminates, and this IRP doesn't
            //  complete within a reasonable time. An alternative would be to explicitly handle cancellation of this IRP.
            //
            //NPROT_WAIT_EVENT(&pOpenContext->PoweredUpEvent, 4500);
            //the following replace NPROT_WAIT_EVENT(&pOpenContext->PoweredUpEvent, 4500); to supress prefast warning 28193
            NdisWaitEvent(&pOpenContext->PoweredUpEvent, 4500);
        }

        if (pOpenContext->PowerState == NetDeviceStateD0) {
            Status = DoRequest(pOpenContext,
                               NDIS_DEFAULT_PORT_NUMBER,
                               RequestType,
                               Oid,
                               InformationBuffer,
                               InformationBufferLength,
                               pBytesProcessed);
        } else {
            Status = NDIS_STATUS_ADAPTER_NOT_READY;
        }

        NPROT_ACQUIRE_LOCK(&pOpenContext->Lock, FALSE);

        //  Let go of the binding.
        pOpenContext->PendedSendCount--;
        if ((NPROT_TEST_FLAGS(pOpenContext->Flags, NPROTO_BIND_FLAGS, NPROTO_BIND_CLOSING)) && (pOpenContext->PendedSendCount == 0)) {
            ASSERT(pOpenContext->ClosingEvent != NULL);
            NPROT_SIGNAL_EVENT(pOpenContext->ClosingEvent);
            pOpenContext->ClosingEvent = NULL;
        }

        NPROT_RELEASE_LOCK(&pOpenContext->Lock, FALSE);
    } while (FALSE);

    DEBUGP(DL_LOUD, ("ValidateOpenAndDoReq: Open %p/%x, OID %x, Status %x\n", pOpenContext, pOpenContext->Flags, Oid, Status));

    return (Status);
}


VOID RequestComplete(IN NDIS_HANDLE       ProtocolBindingContext,
                     IN PNDIS_OID_REQUEST pNdisRequest,
                     IN NDIS_STATUS       Status
)
/*++
Routine Description:
    NDIS entry point indicating completion of a pended NDIS_REQUEST.
Arguments:
    ProtocolBindingContext - pointer to open context
    pNdisRequest - pointer to NDIS request
    Status - status of reset completion
--*/
{
    POPEN_CONTEXT pOpenContext = (POPEN_CONTEXT)ProtocolBindingContext;
    PREQUEST      pReqContext;

    NPROT_STRUCT_ASSERT(pOpenContext, oc);

    pReqContext = CONTAINING_RECORD(pNdisRequest, REQUEST, Request);//  Get at the request context.    
    pReqContext->Status = Status;//  Save away the completion status.    
    NPROT_SIGNAL_EVENT(&pReqContext->ReqEvent);//  Wake up the thread blocked for this request to complete.
}


VOID StatusHandlerEx(IN NDIS_HANDLE ProtocolBindingContext, IN PNDIS_STATUS_INDICATION StatusIndication)
/*++
Routine Description:
    Protocol entry point called by NDIS to indicate a change in status at the miniport.
    We make note of reset and media connect status indications.
Arguments:
    ProtocolBindingContext - pointer to open context
    StatusIndication - pointer to NDIS_STATUS_INDICATION
--*/
{
    POPEN_CONTEXT    pOpenContext = (POPEN_CONTEXT)ProtocolBindingContext;
    NDIS_STATUS      GeneralStatus;
    PNDIS_LINK_STATE LinkState;

    NPROT_STRUCT_ASSERT(pOpenContext, oc);

    if ((StatusIndication->Header.Type != NDIS_OBJECT_TYPE_STATUS_INDICATION) ||
        (StatusIndication->Header.Size != sizeof(NDIS_STATUS_INDICATION))) {
        DEBUGP(DL_INFO, ("Status: Received an invalid status indication: Open %p, StatusIndication %p\n", pOpenContext, StatusIndication));
        return;
    }

    GeneralStatus = StatusIndication->StatusCode;

    DEBUGP(DL_INFO, ("Status: Open %p, Status %x\n", pOpenContext, GeneralStatus));

    NPROT_ACQUIRE_LOCK(&pOpenContext->Lock, FALSE);

    do {
        if (pOpenContext->PowerState != NetDeviceStateD0) {
            //  The device is in a low power state.

            //  We continue and make note of status indications

            //  NOTE that any actions we take based on these
            //  status indications should take into account the current device power state.
        }

        switch (GeneralStatus) {
        case NDIS_STATUS_RESET_START:
            NPROT_ASSERT(!NPROT_TEST_FLAGS(pOpenContext->Flags, NPROTO_RESET_FLAGS, NPROTO_RESET_IN_PROGRESS));
            NPROT_SET_FLAGS(pOpenContext->Flags, NPROTO_RESET_FLAGS, NPROTO_RESET_IN_PROGRESS);
            break;
        case NDIS_STATUS_RESET_END:
            NPROT_ASSERT(NPROT_TEST_FLAGS(pOpenContext->Flags, NPROTO_RESET_FLAGS, NPROTO_RESET_IN_PROGRESS));
            NPROT_SET_FLAGS(pOpenContext->Flags, NPROTO_RESET_FLAGS, NPROTO_NOT_RESETTING);
            break;
        case NDIS_STATUS_LINK_STATE:
            ASSERT(StatusIndication->StatusBufferSize >= sizeof(NDIS_LINK_STATE));
            LinkState = (PNDIS_LINK_STATE)StatusIndication->StatusBuffer;
            if (LinkState->MediaConnectState == MediaConnectStateConnected) {
                NPROT_SET_FLAGS(pOpenContext->Flags, NPROTO_MEDIA_FLAGS, NPROTO_MEDIA_CONNECTED);
            } else {
                NPROT_SET_FLAGS(pOpenContext->Flags, NPROTO_MEDIA_FLAGS, NPROTO_MEDIA_DISCONNECTED);
            }

            break;
        default:
            break;
        }
    } while (FALSE);

    NPROT_RELEASE_LOCK(&pOpenContext->Lock, FALSE);
}


NDIS_STATUS WriteString(_Out_writes_bytes_to_(OutputLength, *pBytesWritten) PUCHAR pBuffer,
                        _In_  ULONG        OutputLength,
                        _Out_ PULONG       pBytesWritten,
                        _In_  PNDIS_STRING String
)
/*++
Routine Description:
    Writes an NDIS_STRING to an output buffer as a NULL-terminated string
Arguments:
    pBuffer - output buffer
    OutputLength - size of pBuffer
    pBytesWritten - receives the number of bytes written to pBuffer
    String - NDIS_STRING to write
Return Value:
    NDIS_STATUS_SUCCESS if successful
    NDIS_STATUS_BUFFER_OVERFLOW if OutputLength is insufficient
--*/
{
    ULONG BytesNeeded = String->Length + sizeof(UNICODE_NULL);

    if (OutputLength < BytesNeeded) {
        return NDIS_STATUS_BUFFER_OVERFLOW;
    }

    NPROT_COPY_MEM(pBuffer, String->Buffer, String->Length);
    *(PWCHAR)(pBuffer + String->Length) = UNICODE_NULL;

    *pBytesWritten = BytesNeeded;
    return NDIS_STATUS_SUCCESS;
}


NDIS_STATUS QueryBinding(_Inout_updates_bytes_to_(OutputLength, *pBytesReturned) PUCHAR pBuffer,
                         _In_  ULONG InputLength,
                         _In_  ULONG OutputLength,
                         _Out_ PULONG pBytesReturned
)
/*++
Routine Description:
    Return information about the specified binding.
Arguments:
    pBuffer - pointer to QUERY_BINDING
    InputLength - input buffer size
    OutputLength - output buffer size
    pBytesReturned - place to return copied byte count.
Return Value:
    NDIS_STATUS_SUCCESS if successful, failure code otherwise.
--*/
{
    PQUERY_BINDING pQueryBinding;
    POPEN_CONTEXT  pOpenContext;
    PLIST_ENTRY    pEnt;
    ULONG          BindingIndex;
    NDIS_STATUS    Status;
    ULONG          DeviceNameOffset;
    ULONG          DeviceDescrOffset;
    ULONG          StringBytesWritten;

    do {
        *pBytesReturned = 0;

        if (InputLength < sizeof(QUERY_BINDING)) {
            Status = NDIS_STATUS_RESOURCES;
            break;
        }

        if (OutputLength < sizeof(QUERY_BINDING)) {
            Status = NDIS_STATUS_BUFFER_OVERFLOW;
            break;
        }

        pQueryBinding = (PQUERY_BINDING)pBuffer;
        BindingIndex = pQueryBinding->BindingIndex;
        Status = NDIS_STATUS_ADAPTER_NOT_FOUND;
        pOpenContext = NULL;

        NPROT_ACQUIRE_LOCK(&Globals.GlobalLock, FALSE);

        for (pEnt = Globals.OpenList.Flink; pEnt != &Globals.OpenList; pEnt = pEnt->Flink) {
            pOpenContext = CONTAINING_RECORD(pEnt, OPEN_CONTEXT, Link);
            NPROT_STRUCT_ASSERT(pOpenContext, oc);

            NPROT_ACQUIRE_LOCK(&pOpenContext->Lock, FALSE);

            //  Skip if not bound.
            if (!NPROT_TEST_FLAGS(pOpenContext->Flags, NPROTO_BIND_FLAGS, NPROTO_BIND_ACTIVE)) {
                NPROT_RELEASE_LOCK(&pOpenContext->Lock, FALSE);
                continue;
            }

            if (BindingIndex == 0) {
                //  Got the binding we are looking for.
                //  Copy the device name and description strings to the output buffer.
                DEBUGP(DL_INFO, ("QueryBinding: found open %p\n", pOpenContext));

                pQueryBinding->DeviceNameOffset = 0;
                pQueryBinding->DeviceNameLength = pOpenContext->DeviceName.Length;
                pQueryBinding->DeviceDescrOffset = 0;
                pQueryBinding->DeviceDescrLength = pOpenContext->DeviceDescr.Length;

                *pBytesReturned = sizeof(QUERY_BINDING);

                // Copy the DeviceName string
                DeviceNameOffset = sizeof(QUERY_BINDING);
                Status = WriteString(pBuffer + DeviceNameOffset,
                                     OutputLength - DeviceNameOffset,
                                     &StringBytesWritten,
                                     &pOpenContext->DeviceName);
                if (NDIS_STATUS_SUCCESS != Status) {
                    NPROT_RELEASE_LOCK(&pOpenContext->Lock, FALSE);
                    break;
                }

                pQueryBinding->DeviceNameOffset = DeviceNameOffset;
                *pBytesReturned += StringBytesWritten;

                DeviceDescrOffset = DeviceNameOffset + StringBytesWritten;// Copy the DeviceDescr string
                Status = WriteString(pBuffer + DeviceDescrOffset,
                                     OutputLength - DeviceDescrOffset,
                                     &StringBytesWritten,
                                     &pOpenContext->DeviceDescr);
                if (NDIS_STATUS_SUCCESS != Status) {
                    NPROT_RELEASE_LOCK(&pOpenContext->Lock, FALSE);
                    break;
                }

                pQueryBinding->DeviceDescrOffset = DeviceDescrOffset;
                *pBytesReturned += StringBytesWritten;

                NPROT_RELEASE_LOCK(&pOpenContext->Lock, FALSE);

                Status = NDIS_STATUS_SUCCESS;
                break;
            }

            NPROT_RELEASE_LOCK(&pOpenContext->Lock, FALSE);

            BindingIndex--;
        }

        NPROT_RELEASE_LOCK(&Globals.GlobalLock, FALSE);
    } while (FALSE);

    return (Status);
}


POPEN_CONTEXT LookupDevice(_In_reads_bytes_(BindingInfoLength) IN PUCHAR pBindingInfo, IN ULONG BindingInfoLength)
/*++
Routine Description:
    Search our global list for an open context structure that has a binding to the specified device,
    and return a pointer to it.

    NOTE: we reference the open that we return.
Arguments:
    pBindingInfo - pointer to unicode device name string
    BindingInfoLength - length in bytes of the above.
Return Value:
    Pointer to the matching open context if found, else NULL
--*/
{
    POPEN_CONTEXT pOpenContext = NULL;
    PLIST_ENTRY   pEnt;

    NPROT_ACQUIRE_LOCK(&Globals.GlobalLock, FALSE);

    for (pEnt = Globals.OpenList.Flink; pEnt != &Globals.OpenList; pEnt = pEnt->Flink) {
        pOpenContext = CONTAINING_RECORD(pEnt, OPEN_CONTEXT, Link);
        NPROT_STRUCT_ASSERT(pOpenContext, oc);

        //  Check if this has the name we are looking for.
        if ((pOpenContext->DeviceName.Length == BindingInfoLength) &&
            NPROT_MEM_CMP(pOpenContext->DeviceName.Buffer, pBindingInfo, BindingInfoLength)) {

            NPROT_REF_OPEN(pOpenContext);   // ref added by LookupDevice
            break;
        }

        pOpenContext = NULL;
    }

    NPROT_RELEASE_LOCK(&Globals.GlobalLock, FALSE);

    return (pOpenContext);
}


NDIS_STATUS QueryOidValue(IN  POPEN_CONTEXT pOpenContext,
                          OUT PVOID pDataBuffer,
                          IN  ULONG BufferLength,
                          OUT PULONG pBytesWritten
)
/*++
Routine Description:
    Query an arbitrary OID value from the miniport.
Arguments:
    pOpenContext - pointer to open context representing our binding to the miniport
    pDataBuffer - place to store the returned value
    BufferLength - length of the above
    pBytesWritten - place to return length returned
Return Value:
    NDIS_STATUS_SUCCESS if we successfully queried the OID.
    NDIS_STATUS_XXX error code otherwise.
--*/
{
    NDIS_STATUS Status;
    PQUERY_OID  pQuery;
    NDIS_OID    Oid = 0;

    do {
        if (BufferLength < sizeof(QUERY_OID)) {
            Status = NDIS_STATUS_BUFFER_TOO_SHORT;
            break;
        }

        pQuery = (PQUERY_OID)pDataBuffer;
        Oid = pQuery->Oid;

        NPROT_ACQUIRE_LOCK(&pOpenContext->Lock, FALSE);

        if (!NPROT_TEST_FLAGS(pOpenContext->Flags, NPROTO_BIND_FLAGS, NPROTO_BIND_ACTIVE)) {
            DEBUGP(DL_WARN, ("QueryOid: Open %p/%x is in invalid state\n", pOpenContext, pOpenContext->Flags));
            NPROT_RELEASE_LOCK(&pOpenContext->Lock, FALSE);
            Status = NDIS_STATUS_FAILURE;
            break;
        }

        pOpenContext->PendedSendCount++;//  Make sure the binding doesn't go away.

        NPROT_RELEASE_LOCK(&pOpenContext->Lock, FALSE);

        Status = DoRequest(pOpenContext,
                           pQuery->PortNumber,
                           NdisRequestQueryInformation,
                           Oid,
                           &pQuery->Data[0],
                           BufferLength - FIELD_OFFSET(QUERY_OID, Data),
                           pBytesWritten);

        NPROT_ACQUIRE_LOCK(&pOpenContext->Lock, FALSE);

        //  Let go of the binding.
        pOpenContext->PendedSendCount--;
        if ((NPROT_TEST_FLAGS(pOpenContext->Flags, NPROTO_BIND_FLAGS, NPROTO_BIND_CLOSING)) && (pOpenContext->PendedSendCount == 0)) {
            ASSERT(pOpenContext->ClosingEvent != NULL);
            NPROT_SIGNAL_EVENT(pOpenContext->ClosingEvent);
            pOpenContext->ClosingEvent = NULL;
        }

        NPROT_RELEASE_LOCK(&pOpenContext->Lock, FALSE);

        if (Status == NDIS_STATUS_SUCCESS) {
            *pBytesWritten += FIELD_OFFSET(QUERY_OID, Data);
        }
    } while (FALSE);

    DEBUGP(DL_LOUD, ("QueryOid: Open %p/%x, OID %x, Status %x\n", pOpenContext, pOpenContext->Flags, Oid, Status));

    return (Status);
}


NDIS_STATUS SetOidValue(IN  POPEN_CONTEXT pOpenContext, OUT PVOID pDataBuffer, IN  ULONG BufferLength)
/*++
Routine Description:
    Set an arbitrary OID value to the miniport.
Arguments:
    pOpenContext - pointer to open context representing our binding to the miniport
    pDataBuffer - buffer that contains the value to be set
    BufferLength - length of the above
Return Value:
    NDIS_STATUS_SUCCESS if we successfully set the OID
    NDIS_STATUS_XXX error code otherwise.
--*/
{
    NDIS_STATUS Status;
    PSET_OID    pSet;
    NDIS_OID    Oid = 0;
    ULONG       BytesWritten;

    do {
        if (BufferLength < sizeof(SET_OID)) {
            Status = NDIS_STATUS_BUFFER_TOO_SHORT;
            break;
        }

        pSet = (PSET_OID)pDataBuffer;
        Oid = pSet->Oid;

        // We should check the OID is settable by the user mode apps
        if (!ValidOid(Oid)) {
            DEBUGP(DL_WARN, ("SetOid: Oid %x cannot be set\n", Oid));
            Status = NDIS_STATUS_INVALID_DATA;
            break;
        }

        NPROT_ACQUIRE_LOCK(&pOpenContext->Lock, FALSE);

        if (!NPROT_TEST_FLAGS(pOpenContext->Flags, NPROTO_BIND_FLAGS, NPROTO_BIND_ACTIVE)) {
            DEBUGP(DL_WARN, ("SetOid: Open %p/%x is in invalid state\n", pOpenContext, pOpenContext->Flags));
            NPROT_RELEASE_LOCK(&pOpenContext->Lock, FALSE);
            Status = NDIS_STATUS_FAILURE;
            break;
        }

        pOpenContext->PendedSendCount++;//  Make sure the binding doesn't go away.

        NPROT_RELEASE_LOCK(&pOpenContext->Lock, FALSE);

        Status = DoRequest(pOpenContext,
                           pSet->PortNumber,
                           NdisRequestSetInformation,
                           Oid,
                           &pSet->Data[0],
                           BufferLength - FIELD_OFFSET(SET_OID, Data),
                           &BytesWritten);

        NPROT_ACQUIRE_LOCK(&pOpenContext->Lock, FALSE);

        //  Let go of the binding.
        pOpenContext->PendedSendCount--;
        if ((NPROT_TEST_FLAGS(pOpenContext->Flags, NPROTO_BIND_FLAGS, NPROTO_BIND_CLOSING)) && (pOpenContext->PendedSendCount == 0)) {
            ASSERT(pOpenContext->ClosingEvent != NULL);
            NPROT_SIGNAL_EVENT(pOpenContext->ClosingEvent);
            pOpenContext->ClosingEvent = NULL;
        }

        NPROT_RELEASE_LOCK(&pOpenContext->Lock, FALSE);
    } while (FALSE);

    DEBUGP(DL_LOUD, ("SetOid: Open %p/%x, OID %x, Status %x\n", pOpenContext, pOpenContext->Flags, Oid, Status));

    return (Status);
}


BOOLEAN ValidOid(IN  NDIS_OID Oid)
/*++
Routine Description:
    Validate whether the given set OID is settable or not.
Arguments:
    Oid - The OID which the user tries to set.
Return Value:
    TRUE if the OID is allowed to set
    FALSE otherwise.
--*/
{
    UINT i;
    UINT NumOids = sizeof(g_SupportedSetOids) / sizeof(NDIS_OID);

    for (i = 0; i < NumOids; i++) {
        if (g_SupportedSetOids[i] == Oid) {
            break;
        }
    }

    return (i < NumOids);
}


VOID
#pragma warning(suppress:6262) // Function is only 22 bytes over the 1k guideline, reasonable enough.
Restart(IN POPEN_CONTEXT pOpenContext, IN PNDIS_PROTOCOL_RESTART_PARAMETERS  RestartParameters)
/*++
Routine Description:
    Handle restart attributes changes.
Arguments:
    pOpenContext - pointer to open context
    RestartParameters - pointer to ndis restart parameters
Return Value:
    None
NOTE: Protocols should query any attribute:
      1. the attribute is not included in the RestartAttributes
  and 2. The protocol cares about whether the attributes is changed by underlying driver.
--*/
{
    ULONG           Length;
    ULONG           TotalLength = 0;
    PUCHAR          Buffer;
    ULONG           BufferLength;
#define NPROT_MAX_FILTER_NAME_LENGTH          512
    WCHAR           FilterNameBuffer[NPROT_MAX_FILTER_NAME_LENGTH];
    PNDIS_RESTART_ATTRIBUTES          NdisRestartAttributes;
    PNDIS_RESTART_GENERAL_ATTRIBUTES  NdisGeneralAttributes;

    DEBUGP(DL_LOUD, ("Restart: Open %p", pOpenContext));

    // Check the filter stack changes
    if (RestartParameters->FilterModuleNameBuffer != NULL) {
        Buffer = RestartParameters->FilterModuleNameBuffer;
        while (RestartParameters->FilterModuleNameBufferLength > TotalLength) {
            BufferLength = *(PUSHORT)Buffer;
            TotalLength += BufferLength + sizeof(USHORT);
            Length = BufferLength + sizeof(USHORT);

            if (BufferLength >= (NPROT_MAX_FILTER_NAME_LENGTH * sizeof(WCHAR))) {
                BufferLength = (NPROT_MAX_FILTER_NAME_LENGTH - 1) * sizeof(WCHAR);
            }
            NdisMoveMemory(FilterNameBuffer, Buffer + sizeof(USHORT), BufferLength);

            BufferLength /= sizeof(WCHAR);

            // BufferLength is bounded by the check above. Check again to suppress prefast warning
            if (BufferLength < NPROT_MAX_FILTER_NAME_LENGTH) {
                FilterNameBuffer[BufferLength] = 0;
            }

            DEBUGP(DL_INFO, ("Filter: %ws\n", FilterNameBuffer));

            Buffer += Length;
        }
    }

    NdisRestartAttributes = RestartParameters->RestartAttributes;// Checked for updated attributes

    // NdisProt is only interested in the generic attributes.
    while (NdisRestartAttributes != NULL) {
        if (NdisRestartAttributes->Oid == OID_GEN_MINIPORT_RESTART_ATTRIBUTES) {
            break;
        }
        NdisRestartAttributes = NdisRestartAttributes->Next;
    }

    // Pick up the new attributes of interest
    if (NdisRestartAttributes != NULL) {
        NdisGeneralAttributes = (PNDIS_RESTART_GENERAL_ATTRIBUTES)NdisRestartAttributes->Data;
        pOpenContext->MacOptions = NdisGeneralAttributes->MacOptions;
        pOpenContext->MaxFrameSize = NdisGeneralAttributes->MtuSize;
    }

    DEBUGP(DL_LOUD, ("Restart: Open %p", pOpenContext));
}
