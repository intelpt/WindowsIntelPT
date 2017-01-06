/**********************************************************************
 *  Windows Intel Processor Trace (PT) Driver
 * 	Filename: DriverIo.cpp
 *	Implements the I/O communication between the Driver and the User App
 *	Last revision: 01/06/2016
 *
 *  Copyright© 2016 Andrea Allievi, Richard Johnson 
 * 	Microsoft Ltd & TALOS Research and Intelligence Group
 *	All right reserved
 **********************************************************************/
#include "stdafx.h"
#include "DriverEntry.h"
#include "DriverIo.h"
#include "UndocNt.h"
#include "Debug.h"

// Driver generic pass-through routine
NTSTATUS DevicePassThrough(PDEVICE_OBJECT pDevObj, PIRP pIrp) 
{
	UNREFERENCED_PARAMETER(pDevObj);
	NTSTATUS ntStatus = STATUS_SUCCESS;
	pIrp->IoStatus.Status = ntStatus;
	pIrp->IoStatus.Information = 0;
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);
	return ntStatus;
}

// Driver unsupported routine
NTSTATUS DeviceUnsupported(PDEVICE_OBJECT pDevObj, PIRP pIrp) 
{
	UNREFERENCED_PARAMETER(pDevObj);
	NTSTATUS ntStatus = STATUS_NOT_SUPPORTED;
	pIrp->IoStatus.Status = ntStatus;
	pIrp->IoStatus.Information = 0;
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);
	return ntStatus;
}

// Driver create and close routine (pass through)
NTSTATUS DeviceCreate(PDEVICE_OBJECT pDevObj, PIRP pIrp) 
{ 
	return DevicePassThrough(pDevObj, pIrp); 
}	

NTSTATUS DeviceClose(PDEVICE_OBJECT pDevObj, PIRP pIrp) 
{ 
	return DevicePassThrough(pDevObj, pIrp); 
}

// The IOCTL dispatch routine
NTSTATUS DeviceIoControl(PDEVICE_OBJECT pDevObj, PIRP pIrp) 
{
	UNREFERENCED_PARAMETER(pDevObj);
	NTSTATUS ntStatus = STATUS_SUCCESS;					// Returned NTSTATUS
	PIO_STACK_LOCATION pIoStack = NULL;					// The I/O stack location
	DWORD dwInBuffSize = 0, dwOutBuffSize = 0;			// Input and output buffer size
	LPVOID lpOutBuff = NULL, lpInBuff = NULL;			// Input and output buffer
	KDPC * pkDpc = NULL;								// The target DPC (must be in NonPaged pool)
	ULONG dwCurCpu = 0, dwNumOfCpus = 0;				// Current processor number
	KAFFINITY kCpusAffinity = 0;						
	DWORD dwTargetCpu = 0;
	BOOLEAN bPause = FALSE;								// TRUE if we need to pause the trace
	IPI_DPC_STRUCT * pIpiDpcStruct = NULL;				// The IPC DPC struct

	pIoStack = IoGetCurrentIrpStackLocation(pIrp);
	dwInBuffSize = pIoStack->Parameters.DeviceIoControl.InputBufferLength;
	dwOutBuffSize = pIoStack->Parameters.DeviceIoControl.OutputBufferLength;

	dwNumOfCpus = KeQueryActiveProcessorCount(&kCpusAffinity);

	// Allocate the needed DPC structure (in Non Paged pool)
	pkDpc = (PKDPC)ExAllocatePoolWithTag(NonPagedPool, sizeof(KDPC), MEMTAG);
	pIpiDpcStruct = (IPI_DPC_STRUCT*)ExAllocatePoolWithTag(NonPagedPool, sizeof(IPI_DPC_STRUCT), MEMTAG);
	if (!pkDpc || !pIpiDpcStruct) 
		return STATUS_INSUFFICIENT_RESOURCES;
	RtlZeroMemory(pkDpc, sizeof(KDPC)); RtlZeroMemory(pIpiDpcStruct, sizeof(IPI_DPC_STRUCT));

	switch (pIoStack->Parameters.DeviceIoControl.IoControlCode) 
	{
		// Check the support for current processor and get the capabilities list
		case IOCTL_PTDRV_CHECKSUPPORT: 
		{
			// Input buffer: none
			// Output buffer: an optional QWORD value that contains the PT capabilities
			INTEL_PT_CAPABILITIES ptCap = { 0 };
			ntStatus = CheckIntelPtSupport(&ptCap);

			if (dwOutBuffSize >= sizeof(INTEL_PT_CAPABILITIES)) {
				RtlCopyMemory(pIrp->AssociatedIrp.SystemBuffer, &ptCap, sizeof(INTEL_PT_CAPABILITIES));
				pIrp->IoStatus.Information = sizeof(INTEL_PT_CAPABILITIES);
			} else {
				ntStatus = STATUS_NOT_IMPLEMENTED;
			}
			break;
		}

		// Start a particular process trace
		case IOCTL_PTDRV_START_TRACE: 
		{
			// Input buffer:  a PT_USER_REQ that describes the tracing information
			// Output buffer: a pointer to the new physical buffer that contains the trace
			PT_USER_REQ * ptTraceStruct = NULL;
			PEPROCESS epTarget = NULL;				// Target EPROCESS (if any)
			lpInBuff = pIrp->AssociatedIrp.SystemBuffer;
			lpOutBuff = pIrp->AssociatedIrp.SystemBuffer;

			if (dwInBuffSize < sizeof(PT_USER_REQ)) {
				ntStatus = STATUS_INVALID_BUFFER_SIZE;
				break;
			}
			ptTraceStruct = (PT_USER_REQ*)lpInBuff;

			dwTargetCpu = ptTraceStruct->dwCpuId;
			if (dwTargetCpu == (ULONG)-1) {
				// XXX: Tracing all processes is currently not implemented
				ntStatus = STATUS_NOT_IMPLEMENTED;
				break;
			} else if (dwTargetCpu >= dwNumOfCpus) {
				ntStatus = STATUS_INVALID_PARAMETER;
				break;
			}

			// Grab the EPROCESS structure (if any)
			if (ptTraceStruct->dwProcessId > 0) {
				ntStatus = PsLookupProcessByProcessId((HANDLE)ptTraceStruct->dwProcessId, &epTarget);
				if (!NT_SUCCESS(ntStatus)) {
					ntStatus = STATUS_INVALID_PARAMETER;
					break;
				}
			}
			// Verify here that the ranges are correct
			int iNumOfRanges = ptTraceStruct->IpFiltering.dwNumOfRanges;
			if (iNumOfRanges >= 4) { ntStatus = STATUS_INVALID_PARAMETER; break; }
	
			#ifndef _KERNEL_TRACE_FROM_USER_MODE_ENABLED
			BOOLEAN bIpWindowError = FALSE;
			for (int i = 0; i < iNumOfRanges; i++) {
				PT_TRACE_IP_FILTERING & filterDesc = ptTraceStruct->IpFiltering;
				if ((ULONG_PTR)filterDesc.Ranges[i].lpStartVa > (ULONG_PTR)MmHighestUserAddress ||
					(ULONG_PTR)filterDesc.Ranges[i].lpEndVa > (ULONG_PTR)MmHighestUserAddress) {
					bIpWindowError = TRUE;
					break;
				}
			}
			if (bIpWindowError) { ntStatus = STATUS_INVALID_PARAMETER; break; }
			#endif		

			// Round up buffer size to be page aligned
			ptTraceStruct->dwTraceSize = ROUND_TO_PAGES(ptTraceStruct->dwTraceSize);

			// Allocate and run the DPC
			pIpiDpcStruct->dwCpu = dwTargetCpu; 
			pIpiDpcStruct->Type = DPC_TYPE_START_PT;
			KeInitializeEvent(&pIpiDpcStruct->kEvt, SynchronizationEvent, FALSE);
			KeInitializeDpc(pkDpc, IoCpuIpiDpc, (PVOID)pIpiDpcStruct);
			KeSetTargetProcessorDpc(pkDpc, (CCHAR)dwTargetCpu);
			KeInsertQueueDpc(pkDpc, (LPVOID)ptTraceStruct, (LPVOID)epTarget); // Method-Buffered: passing ptTraceStruct is safe

			// Wait for the DPC to do its job
			KeWaitForSingleObject((PVOID)&pIpiDpcStruct->kEvt, Executive, KernelMode, FALSE, NULL);
				
			if (lpOutBuff && dwOutBuffSize >= sizeof(LPVOID)) 
			{
				// map physical buffer to usermode
				ntStatus = MapTracePhysBuffToUserVa(dwTargetCpu);
				RtlCopyMemory(lpOutBuff, &g_pDrvData->procData[dwTargetCpu].lpUserVa, sizeof(LPVOID));
				pIrp->IoStatus.Information = sizeof(LPVOID);
			} else
				pIrp->IoStatus.Information = 0;
		
			ntStatus = pIpiDpcStruct->ioSb.Status;
			break;
		}

		// Stop a process trace
		case IOCTL_PTDRV_PAUSE_TRACE:
			bPause = TRUE;
		case IOCTL_PTDRV_RESUME_TRACE:
			// Method buffered
			lpInBuff = pIrp->AssociatedIrp.SystemBuffer;

			if (dwInBuffSize < sizeof(DWORD)) 
			{
				ntStatus = STATUS_INVALID_BUFFER_SIZE;
				break;
			}

			dwTargetCpu = *((DWORD*)lpInBuff);
			dwCurCpu = KeGetCurrentProcessorNumber();
			if (dwTargetCpu == (ULONG)-1) 
			{
				//TODO: Tracing all processors currently not implemented
				ntStatus = STATUS_NOT_IMPLEMENTED;
				break;
			}
			else if (dwTargetCpu >= dwNumOfCpus) {
				ntStatus = STATUS_INVALID_PARAMETER;
				break;
			}

			// Allocate and run the DPC
			pIpiDpcStruct->dwCpu = dwTargetCpu;
			pIpiDpcStruct->Type = DPC_TYPE_PAUSE_PT;
			KeInitializeEvent(&pIpiDpcStruct->kEvt, SynchronizationEvent, FALSE);
			KeInitializeDpc(pkDpc, IoCpuIpiDpc, (PVOID)pIpiDpcStruct);
			KeSetTargetProcessorDpc(pkDpc, (CCHAR)dwTargetCpu);
			KeInsertQueueDpc(pkDpc, (LPVOID)bPause,  NULL);

			// Wait for the DPC to do its job
			KeWaitForSingleObject((PVOID)&pIpiDpcStruct->kEvt, Executive, KernelMode, FALSE, NULL);
			pIrp->IoStatus.Information = 0;
			ntStatus = pIpiDpcStruct->ioSb.Status;
			break;

		// Dump the current trace data
		case IOCTL_PTDRV_CLEAR_TRACE:
			// Method buffered 
			lpInBuff = pIrp->AssociatedIrp.SystemBuffer;

			if (dwInBuffSize < sizeof(DWORD)) {
				ntStatus = STATUS_INVALID_BUFFER_SIZE;
				break;
			}

			dwTargetCpu = *((DWORD*)lpInBuff);
			dwCurCpu = KeGetCurrentProcessorNumber();
			if (dwTargetCpu == (ULONG)-1) {
				//TODO: tracing all processors currently not implemented
				ntStatus = STATUS_NOT_IMPLEMENTED;
				break;
			} else if (dwTargetCpu >= dwNumOfCpus) {
				ntStatus = STATUS_INVALID_PARAMETER;
				break;
			}

			// Try to unmap the user-mode buffer (this will fail if called from within the traced process)
			if (NT_SUCCESS(ntStatus)) {
				PER_PROCESSOR_PT_DATA * pPtData = &g_pDrvData->procData[dwTargetCpu];
				if (pPtData->lpUserVa)
					ntStatus = UnmapTraceBuffToUserVa(dwTargetCpu);
			}

			// Allocate and run the DPC
			pIpiDpcStruct->dwCpu = dwTargetCpu;
			pIpiDpcStruct->Type = DPC_TYPE_CLEAR_PT;
			KeInitializeEvent(&pIpiDpcStruct->kEvt, SynchronizationEvent, FALSE);
			KeInitializeDpc(pkDpc, IoCpuIpiDpc, (PVOID)pIpiDpcStruct);
			KeSetTargetProcessorDpc(pkDpc, (CCHAR)dwTargetCpu);
			KeInsertQueueDpc(pkDpc, NULL, NULL);
			
			// Wait for the DPC to do its job
			KeWaitForSingleObject((PVOID)&pIpiDpcStruct->kEvt, Executive, KernelMode, FALSE, NULL);

			pIrp->IoStatus.Information = 0;
			ntStatus = pIpiDpcStruct->ioSb.Status;
			break;

		case IOCTL_PTDR_GET_TRACE_DETAILS: 
		{
			// Get the trace details (total number of packets, etc)
			lpInBuff = pIrp->AssociatedIrp.SystemBuffer;	// Input buffer: CPU number
			lpOutBuff = pIrp->AssociatedIrp.SystemBuffer;	// Output buffer: PT_TRACE_DETAILS structure

			// Parameters check
			if (dwInBuffSize < sizeof(DWORD) || dwOutBuffSize < sizeof(PT_TRACE_DETAILS)) {
				ntStatus = STATUS_INVALID_BUFFER_SIZE;
				break;
			}

			dwTargetCpu = *((DWORD*)lpInBuff);
			if (dwTargetCpu >= dwNumOfCpus) {
				ntStatus = STATUS_INVALID_PARAMETER;
				break;
			}

			PER_PROCESSOR_PT_DATA & cpuData = g_pDrvData->procData[dwTargetCpu];
			PT_TRACE_DETAILS details = { 0 };
			
			if (cpuData.curState == PT_PROCESSOR_STATE_STOPPED) 
				details.dwCurrentTraceState = PT_TRACE_STATE_STOPPED;
			else if (cpuData.curState == PT_PROCESSOR_STATE_PAUSED) 
				details.dwCurrentTraceState = PT_TRACE_STATE_PAUSED;
			else if (cpuData.curState == PT_PROCESSOR_STATE_TRACING) 
				details.dwCurrentTraceState = PT_TRACE_STATE_RUNNING;
			else 
				details.dwCurrentTraceState = PT_TRACE_STATE_ERROR;

			if (cpuData.lpTargetProc)
				details.dwTargetProcId = (DWORD)PsGetProcessId(cpuData.lpTargetProc);

			details.dwCpuId = dwTargetCpu;
			if (cpuData.pPtBuffDesc) details.dwTraceBuffSize = (DWORD)cpuData.pPtBuffDesc->qwBuffSize;
			details.qwTotalNumberOfPackets = cpuData.PacketByteCount;
			details.IpFiltering.dwNumOfRanges = cpuData.dwNumOfActiveRanges;
			RtlCopyMemory(details.IpFiltering.Ranges, cpuData.IpRanges, cpuData.dwNumOfActiveRanges * sizeof(details.IpFiltering.Ranges[0]));

			RtlCopyMemory(lpOutBuff, &details, sizeof(PT_TRACE_DETAILS));
			pIrp->IoStatus.Information = sizeof(PT_TRACE_DETAILS);
			ntStatus = STATUS_SUCCESS;
			break;
		}

		#ifdef _DEBUG
		case IOCTL_PTDR_DO_KERNELDRV_TEST: {
			// USE this only in test environments:
			lpInBuff = pIrp->AssociatedIrp.SystemBuffer;
			if (dwInBuffSize < 2) return STATUS_INVALID_BUFFER_SIZE;

			DrvDbgPrint("[WindowsPtDriver] Received special Debug IOCTL. Do not use this in production environments!\r\n");
			ntStatus = DoDriverTraceTest((LPTSTR)lpInBuff);
			if (!NT_SUCCESS(ntStatus)) 
				DrvDbgPrint("[WindowsPtDriver] The Kernel mode tracing test has failed with 0x%08X status.", ntStatus);
			pIrp->IoStatus.Information = 0;
			break;
		}
		#endif	
		default:
			ntStatus = STATUS_NOT_SUPPORTED;
			break;
	}

	// Cleanup and complete the request
	if (pIpiDpcStruct) ExFreePool(pIpiDpcStruct);
	if (pkDpc) ExFreePool((LPVOID)pkDpc);
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);
	return ntStatus;
}

#pragma code_seg(".nonpaged")
// DPC routine (needed to start/stop/pause the PT on a target CPU)
/* Arguments explanation:
 *   DeferredContext - Pointer to a structure that describe the DPC itself
 *   SysArg1 - the structure that describe the operation 
 *   SysArg2 - Any data that is not related to the DPC but can not acquired at DISPATCH_LEVEL. Ususally is the pointer to the target process. */
VOID IoCpuIpiDpc(struct _KDPC *Dpc, PVOID DeferredContext, PVOID SysArg1, PVOID SysArg2)
{
	UNREFERENCED_PARAMETER(Dpc);
	IPI_DPC_STRUCT * pIpiDpcStruct = (IPI_DPC_STRUCT*)DeferredContext;
	PT_USER_REQ * ptTraceUserStruct = NULL;
	DWORD dwCpuId = KeGetCurrentProcessorNumber();
	NTSTATUS ntStatus = STATUS_SUCCESS;

	ASSERT(KeGetCurrentIrql() == DISPATCH_LEVEL);

	switch (pIpiDpcStruct->Type) 
	{
		case DPC_TYPE_START_PT: {
			TRACE_OPTIONS opts = { 0 };
			ptTraceUserStruct = (PT_USER_REQ*)SysArg1;
			PEPROCESS pTargetProc = (PEPROCESS)SysArg2;
			if (ptTraceUserStruct->dwOptsMask)	{
				// Analyse here the trace options if any
				opts.All = ptTraceUserStruct->dwOptsMask;
				ntStatus = SetTraceOptions(dwCpuId, opts);
				if (!NT_SUCCESS(ntStatus)) break;
			}

			// Build the PT_TRACE_DESC structure and translate the PT_USER_REQ structure
			PT_TRACE_DESC ptDesc = { 0 };
			#ifndef _KERNEL_TRACE_FROM_USER_MODE_ENABLED
			ptDesc.bTraceKernel = FALSE;
			ptDesc.bTraceUser = TRUE;
			#else		
			ptDesc.bTraceUser = ptTraceUserStruct->bTraceUser;
			ptDesc.bTraceKernel = ptTraceUserStruct->bTraceKernel;
			if (!ptDesc.bTraceKernel && !ptDesc.bTraceUser) ptDesc.bTraceUser = 1;
			#endif		

			ptDesc.peProc = pTargetProc;
			ptDesc.dwNumOfRanges = ptTraceUserStruct->IpFiltering.dwNumOfRanges;
			if (ptDesc.dwNumOfRanges)
				RtlCopyMemory(ptDesc.Ranges, ptTraceUserStruct->IpFiltering.Ranges, sizeof(PT_TRACE_RANGE) * 4);

			// user input validated in DriverIo dispatch function
			ntStatus = StartCpuTrace(ptDesc, (QWORD)ptTraceUserStruct->dwTraceSize);
			break;
		}
		case DPC_TYPE_PAUSE_PT: {
			BOOLEAN bPause = (BOOLEAN)SysArg1;
			ntStatus = PauseResumeTrace(bPause);
			break;
		}
		case DPC_TYPE_CLEAR_PT: {
			ntStatus = StopAndDisablePt();
			FreeCpuResources(dwCpuId);
			break;
		}
	}

	// Raise the event
	pIpiDpcStruct->ioSb.Status = ntStatus;
	KeSetEvent(&pIpiDpcStruct->kEvt, IO_NO_INCREMENT, FALSE);
}

#pragma code_seg()
