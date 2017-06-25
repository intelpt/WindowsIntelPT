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

// Allocate the PT buffer for one or more CPUs
NTSTATUS AllocateCpuUserBuffers(KAFFINITY cpuAffinity, DWORD dwSize, LPVOID * lppBuffArray, DWORD * lpdwArraySize, BOOLEAN bUseToPA) {
	NTSTATUS ntStatus = 0;						// Returned NT_STATUS
	PER_PROCESSOR_PT_DATA * pCurCpuData = NULL;	// Per processor CPU data
	KAFFINITY kSysCpusAffinity = 0;				// The system CPU affinity mask
	DWORD dwCurProcId = 0;						// Current process ID
	DWORD dwNumOfBuffers = 0,					// Number of buffer to allocate
		dwCurIdx = 0;							// Current buffer index
	ULONG_PTR * lpBuffArray = NULL;				// The buffer array

	dwCurProcId = (DWORD)PsGetCurrentProcessId();
	KeQueryActiveProcessorCount(&kSysCpusAffinity);

	// Verify the CPU affinity
	if ((cpuAffinity | kSysCpusAffinity) != kSysCpusAffinity) return STATUS_INVALID_PARAMETER;
	if (dwSize < PAGE_SIZE) return STATUS_INVALID_PARAMETER;

	// Count the number of the CPU -> the number of buffer to allocate
	for (int i = 0; i < sizeof(KAFFINITY); i++) {
		if (!(cpuAffinity & (1i64 << i))) continue;
		pCurCpuData = &g_pDrvData->procData[i];
		if (pCurCpuData->lpUserVa != NULL ||
			(pCurCpuData->pPtBuffDesc && pCurCpuData->pPtBuffDesc->u.Simple.lpTraceBuffPhysAddr))
			// A buffer has been already allocated, the user need to get rid of this before proceed
			return STATUS_ADDRESS_ALREADY_EXISTS;			// STATUS_ALREADY_COMMITTED = 0xC0000021L - No Win32 translation
		dwNumOfBuffers++;
	}

	if (!dwNumOfBuffers) return STATUS_INVALID_PARAMETER;
	DrvDbgPrint("[" DRV_NAME "] Requested the allocation of 0x%08X bytes buffer for %i CPUs (affinity 0x%08X)",
		dwSize, dwNumOfBuffers, cpuAffinity);

	lpBuffArray = (ULONG_PTR*)ExAllocatePoolWithTag(PagedPool, dwNumOfBuffers * sizeof(ULONG_PTR), MEMTAG);
	RtlZeroMemory(lpBuffArray, dwNumOfBuffers * sizeof(ULONG_PTR));
	dwCurIdx = 0;

	for (int i = 0; i < sizeof(KAFFINITY); i++) {
		if (!(cpuAffinity & (1i64 << i))) continue;
		pCurCpuData = &g_pDrvData->procData[i];

		ntStatus = AllocCpuPtBuffer(i, (QWORD)dwSize, bUseToPA);
		if (NT_SUCCESS(ntStatus)) ntStatus = MapTracePhysBuffToUserVa(i);
		if (!NT_SUCCESS(ntStatus)) return ntStatus;
		lpBuffArray[dwCurIdx++] = (ULONG_PTR)pCurCpuData->lpUserVa;
		if (dwCurIdx >= dwNumOfBuffers) break;
	}

	if (lppBuffArray) *lppBuffArray = (LPVOID*)lpBuffArray;
	else ExFreePool(lpBuffArray);
	if (lpdwArraySize) *lpdwArraySize = (dwNumOfBuffers * sizeof(ULONG_PTR));

	return ntStatus;
}

// Free the PT buffer of the specified CPUs
NTSTATUS FreeCpuUserBuffers(KAFFINITY cpuAffinity) {
	NTSTATUS ntStatus = 0;						// Returned NT_STATUS
	KAFFINITY kSysCpusAffinity = 0;				// The system CPU affinity mask
	DWORD dwCurProcId = 0;						// Current process ID

	dwCurProcId = (DWORD)PsGetCurrentProcessId();
	KeQueryActiveProcessorCount(&kSysCpusAffinity);

	// Verify the CPU affinity
	if ((cpuAffinity | kSysCpusAffinity) != kSysCpusAffinity) return STATUS_INVALID_PARAMETER;

	// Count the number of the CPU -> the number of buffer to allocate
	for (int i = 0; i < sizeof(KAFFINITY); i++) {
		if (!(cpuAffinity & (1i64 << i))) continue;
		ntStatus = FreeCpuResources(i);
		if (!NT_SUCCESS(ntStatus)) return ntStatus;
	}
	return STATUS_SUCCESS;
}

// Search a PMI User-mode Callback entry and optionally remove it
#pragma code_seg(".nonpaged")
PMI_USER_CALLBACK_DESC * SearchCallbackEntry(LPVOID lpAddress, DWORD dwThrId, BOOLEAN bRemove) {
	KIRQL kOldIrql = KeGetCurrentIrql();
	PLIST_ENTRY pNextEntry = NULL;
	PPMI_USER_CALLBACK_DESC pFoundPmiDesc = NULL;

	KeAcquireSpinLock(&g_pDrvData->userCallbackListLock, &kOldIrql);
	// Be fast here
	pNextEntry = g_pDrvData->userCallbackList.Flink;
	while (pNextEntry != &g_pDrvData->userCallbackList) {
		PPMI_USER_CALLBACK_DESC pCurPmiDesc = NULL;
		pCurPmiDesc = CONTAINING_RECORD(pNextEntry, PMI_USER_CALLBACK_DESC, entry);
		if (pCurPmiDesc->lpUserAddress == lpAddress && PsGetThreadId(pCurPmiDesc->pTargetThread) == (HANDLE)dwThrId) {
			pFoundPmiDesc = pCurPmiDesc;
			if (bRemove) RemoveEntryList(pNextEntry);
			break;
		}
		pNextEntry = pNextEntry->Flink;
	}
	KeReleaseSpinLock(&g_pDrvData->userCallbackListLock, kOldIrql);
	return pFoundPmiDesc;
}
#pragma code_seg()


// The IOCTL dispatch routine
NTSTATUS DeviceIoControl(PDEVICE_OBJECT pDevObj, PIRP pIrp) 
{
	UNREFERENCED_PARAMETER(pDevObj);
	NTSTATUS ntStatus = STATUS_SUCCESS;					// Returned NTSTATUS
	PIO_STACK_LOCATION pIoStack = NULL;					// The I/O stack location
	DWORD dwInBuffSize = 0, dwOutBuffSize = 0;			// Input and output buffer size
	LPVOID lpOutBuff = NULL, lpInBuff = NULL;			// Input and output buffer
	KDPC * pkDpc = NULL;								// The target DPC (must be in NonPaged pool)
	ULONG dwNumOfCpus = 0;								// Total number of System CPUs
	//ULONG dwCurCpuCounter = 0;							// The current CPU conter (which is very different in respect to the CPU ID)
	KAFFINITY kSysCpusAffinity = 0;						// The system CPU affinity mask
	KAFFINITY kTargetCpusAffinity = 0;					// The target CPU affinity
	BOOLEAN bPause = FALSE;								// TRUE if we need to pause the trace
	IPI_DPC_STRUCT * pIpiDpcStruct = NULL;				// The IPC DPC struct
	PMI_USER_CALLBACK_DESC * pmiUserCallbackDesc = NULL;		// The PMI user callback descriptor (if any)
	PEPROCESS epTarget = NULL;				// Target EPROCESS (if any)
	BOOL epTargetrefCount = 0;							// Track if we hold a reference to an EPROCESS
														// due to PsLookupProcessByProcessId

	pIoStack = IoGetCurrentIrpStackLocation(pIrp);
	dwInBuffSize = pIoStack->Parameters.DeviceIoControl.InputBufferLength;
	dwOutBuffSize = pIoStack->Parameters.DeviceIoControl.OutputBufferLength;

	dwNumOfCpus = KeQueryActiveProcessorCount(&kSysCpusAffinity);

	// Allocate the needed DPC structure (in Non Paged pool)
	pkDpc = (PKDPC)ExAllocatePoolWithTag(NonPagedPool, sizeof(KDPC), MEMTAG);
	pIpiDpcStruct = (IPI_DPC_STRUCT*)ExAllocatePoolWithTag(NonPagedPool, sizeof(IPI_DPC_STRUCT), MEMTAG);
	if (!pkDpc || !pIpiDpcStruct) 
		return STATUS_INSUFFICIENT_RESOURCES;
	RtlZeroMemory(pkDpc, sizeof(KDPC)); RtlZeroMemory(pIpiDpcStruct, sizeof(IPI_DPC_STRUCT));

	switch (pIoStack->Parameters.DeviceIoControl.IoControlCode) 
	{
		#pragma region Utility IOCTLs
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

		// Get the trace details (total number of packets, etc)
		case IOCTL_PTDR_GET_TRACE_DETAILS:
		{
			lpInBuff = pIrp->AssociatedIrp.SystemBuffer;	// Input buffer: CPU number
			lpOutBuff = pIrp->AssociatedIrp.SystemBuffer;	// Output buffer: PT_TRACE_DETAILS structure

			// Parameters check
			if (dwInBuffSize < sizeof(DWORD) || dwOutBuffSize < sizeof(PT_TRACE_DETAILS)) {
				ntStatus = STATUS_INVALID_BUFFER_SIZE;
				break;
			}

			DWORD dwTargetCpu = *((DWORD*)lpInBuff);
			if (dwTargetCpu >= dwNumOfCpus || !(g_pDrvData->kLastCpuAffinity & (1i64 << dwTargetCpu))) {
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
			if (cpuData.pPtBuffDesc)
				details.dwTraceBuffSize = (DWORD)cpuData.pPtBuffDesc->qwBuffSize;
			details.qwTotalNumberOfPackets = cpuData.PacketByteCount;
			details.IpFiltering.dwNumOfRanges = cpuData.dwNumOfActiveRanges;
			RtlCopyMemory(details.IpFiltering.Ranges, cpuData.IpRanges, cpuData.dwNumOfActiveRanges * sizeof(details.IpFiltering.Ranges[0]));

			RtlCopyMemory(lpOutBuff, &details, sizeof(PT_TRACE_DETAILS));
			pIrp->IoStatus.Information = sizeof(PT_TRACE_DETAILS);
			ntStatus = STATUS_SUCCESS;
			break;
		}
		#pragma endregion

		#pragma region Start/Stop - Pause/Resume trace IOCTLs
		// Start PT on one or more CPUs
		case IOCTL_PTDRV_START_TRACE: 
		{
			// Input buffer: a PT_USER_REQ that describes the tracing information
			// Output buffer: an optional array of LPVOID that contains the Virtual addresses of the USER mode buffers
			PT_USER_REQ * ptTraceStruct = NULL;
			DWORD dwTotalNumOfBuffs = 0,			// TOTAL number of buffers
				dwCurNumOfBuff = 0;					// The number of copied buffers
			lpInBuff = pIrp->AssociatedIrp.SystemBuffer;
			lpOutBuff = pIrp->AssociatedIrp.SystemBuffer;

			if (dwInBuffSize < sizeof(PT_USER_REQ)) {
				ntStatus = STATUS_INVALID_BUFFER_SIZE;
				break;
			}
			ptTraceStruct = (PT_USER_REQ*)lpInBuff;

			// Step 1. Parameters checking:
			// Verify the CPU mask affinity
			kTargetCpusAffinity = (KAFFINITY)ptTraceStruct->kCpuAffinity;
			if ((kSysCpusAffinity | kTargetCpusAffinity) != kSysCpusAffinity) {
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
				epTargetrefCount++;
			}
			// Verify here that the ranges are correct
			unsigned int iNumOfRanges = ptTraceStruct->IpFiltering.dwNumOfRanges;
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

			ntStatus = STATUS_UNSUCCESSFUL;
			for (int i = 0; i < sizeof(kTargetCpusAffinity) * 8; i++) {
				if (!(kTargetCpusAffinity & (1i64 << i))) continue;
				PER_PROCESSOR_PT_DATA * pPerCpuData = &g_pDrvData->procData[i];
				QWORD qwBuffSize = IsPtBufferAllocatedAndValid(i, TRUE);
				BOOLEAN bNewVa = FALSE;

				if (qwBuffSize  && pPerCpuData->lpMappedProc != PsGetCurrentProcess()) 
					if (!NT_SUCCESS(UnmapTraceBuffToUserVa(i))) {
						ntStatus = STATUS_CONTEXT_MISMATCH;
						break;
					} else
						bNewVa = TRUE;

				if (qwBuffSize != (QWORD)ptTraceStruct->dwTraceSize || bNewVa) {
					// We need to re-allocate or re-map the buffer
					if (dwOutBuffSize < ((dwTotalNumOfBuffs + 1) * sizeof(LPVOID))) {
						// We do not have space to communicate back the buffer
						ntStatus = STATUS_INVALID_BUFFER_SIZE;
						break;
					}
					DrvDbgPrint("[" DRV_NAME "] (Re)allocating 0x%08X bytes of PT buffer for CPU %i...\r\n",
						ptTraceStruct->dwTraceSize, i);
					BOOLEAN bUseTopa = ((ptTraceStruct->dwOptsMask & PT_ENABLE_TOPA_MASK) != 0);
					if (qwBuffSize != (QWORD)ptTraceStruct->dwTraceSize)
						ntStatus = AllocateCpuUserBuffers((KAFFINITY)(1i64 << i), ptTraceStruct->dwTraceSize, NULL, NULL, bUseTopa);
					else if (bNewVa) 
						// Needs to be remapped here
						ntStatus = MapTracePhysBuffToUserVa(i);
					if (!NT_SUCCESS(ntStatus)) break;
				} else {
					ClearCpuPtBuffer(i);				// It is safe to call this here
					ntStatus = STATUS_SUCCESS;
				}
				dwTotalNumOfBuffs++;
			}
			if (!NT_SUCCESS(ntStatus)) break;

			// Reset the PMI event before start
			if (g_pDrvData->pPmiEvent)
				KeClearEvent(g_pDrvData->pPmiEvent);
			
			for (int iCpuNum = 0; iCpuNum < sizeof(kTargetCpusAffinity) * 8; iCpuNum++) {
				if (!(kTargetCpusAffinity & (1i64 << iCpuNum))) continue;

				// Allocate and run the DPC
				RtlZeroMemory(pIpiDpcStruct, sizeof(IPI_DPC_STRUCT));
				pIpiDpcStruct->dwCpu = iCpuNum;
				pIpiDpcStruct->Type = DPC_TYPE_START_PT;
				KeInitializeEvent(&pIpiDpcStruct->kEvt, SynchronizationEvent, FALSE);
				KeInitializeDpc(pkDpc, IoCpuIpiDpc, (PVOID)pIpiDpcStruct);
				KeSetTargetProcessorDpc(pkDpc, (CCHAR)iCpuNum);
				KeInsertQueueDpc(pkDpc, (LPVOID)ptTraceStruct, (LPVOID)epTarget); // Method-Buffered: passing ptTraceStruct is safe

				// Wait for the DPC to do its job
				KeWaitForSingleObject((PVOID)&pIpiDpcStruct->kEvt, Executive, KernelMode, FALSE, NULL);
				ntStatus = pIpiDpcStruct->ioSb.Status;
				if (!NT_SUCCESS(ntStatus)) break;
			}
			if (!NT_SUCCESS(ntStatus)) break;

			// Now copy the buffers (if needed)
			for (dwCurNumOfBuff = 0; dwCurNumOfBuff < dwTotalNumOfBuffs; dwCurNumOfBuff++) {
				LPVOID * lpBuffArray = (LPVOID*)lpOutBuff;
				if (dwOutBuffSize >= (dwCurNumOfBuff + 1) * sizeof(LPVOID))
					lpBuffArray[dwCurNumOfBuff] = g_pDrvData->procData[dwCurNumOfBuff].lpUserVa;
				else
					break;
			}
			
			// Set the last CPU affinity
			g_pDrvData->kLastCpuAffinity = kTargetCpusAffinity;

			pIrp->IoStatus.Information = dwCurNumOfBuff * sizeof(LPVOID);
			ntStatus = STATUS_SUCCESS;
			break;
		}

		// Stop a process trace
		case IOCTL_PTDRV_PAUSE_TRACE:
			bPause = TRUE;
		case IOCTL_PTDRV_RESUME_TRACE:
			// Method buffered
			lpInBuff = pIrp->AssociatedIrp.SystemBuffer;

			if (dwInBuffSize == sizeof(DWORD)) 
				kTargetCpusAffinity = (KAFFINITY)(*(DWORD*)lpInBuff);
			else if (dwInBuffSize >= sizeof(KAFFINITY))
				kTargetCpusAffinity = (*(KAFFINITY*)lpInBuff);
			else {
				ntStatus = STATUS_INVALID_BUFFER_SIZE;
				break;
			}

			for (int iCpuNum = 0; iCpuNum < sizeof(kTargetCpusAffinity); iCpuNum++) {
				if (!(kTargetCpusAffinity & (1i64 << iCpuNum))) continue;

				// Allocate and run the DPC
				RtlZeroMemory(pIpiDpcStruct, sizeof(IPI_DPC_STRUCT));
				pIpiDpcStruct->dwCpu = iCpuNum;
				pIpiDpcStruct->Type = DPC_TYPE_PAUSE_PT;
				KeInitializeEvent(&pIpiDpcStruct->kEvt, SynchronizationEvent, FALSE);
				KeInitializeDpc(pkDpc, IoCpuIpiDpc, (PVOID)pIpiDpcStruct);
				KeSetTargetProcessorDpc(pkDpc, (CCHAR)iCpuNum);
				KeInsertQueueDpc(pkDpc, (LPVOID)bPause, NULL);

				// Wait for the DPC to do its job
				KeWaitForSingleObject((PVOID)&pIpiDpcStruct->kEvt, Executive, KernelMode, FALSE, NULL);
				if (!NT_SUCCESS(pIpiDpcStruct->ioSb.Status)) break;
			}
			pIrp->IoStatus.Information = 0;
			ntStatus = pIpiDpcStruct->ioSb.Status;
			break;

		// Stop and clear Intel PT on one or more processors
		case IOCTL_PTDRV_CLEAR_TRACE:
			// Input buffer:  a DWORD or QWORD that contains the CPU affinity mask
			// Output buffer: None
			lpInBuff = pIrp->AssociatedIrp.SystemBuffer;

			if (dwInBuffSize == sizeof(DWORD))
				kTargetCpusAffinity = (KAFFINITY)(*(DWORD*)lpInBuff);
			else if (dwInBuffSize >= sizeof(KAFFINITY))
				kTargetCpusAffinity = (*(KAFFINITY*)lpInBuff);
			else {
				ntStatus = STATUS_INVALID_BUFFER_SIZE;
				break;
			}

			// Verify the CPU mask affinity
			if ((kSysCpusAffinity | kTargetCpusAffinity) != kSysCpusAffinity) {
				ntStatus = STATUS_INVALID_PARAMETER;
				break;
			}

			for (int iCpuNum = 0; iCpuNum < sizeof(kTargetCpusAffinity); iCpuNum++) {
				if (!(kTargetCpusAffinity & (1i64 << iCpuNum))) continue;

				if (!g_pDrvData->bManualAllocBuff)
					UnmapTraceBuffToUserVa((DWORD)iCpuNum);

				// Allocate and run the DPC
				RtlZeroMemory(pIpiDpcStruct, sizeof(IPI_DPC_STRUCT));
				pIpiDpcStruct->dwCpu = iCpuNum;
				pIpiDpcStruct->Type = DPC_TYPE_CLEAR_PT;
				KeInitializeEvent(&pIpiDpcStruct->kEvt, SynchronizationEvent, FALSE);
				KeInitializeDpc(pkDpc, IoCpuIpiDpc, (PVOID)pIpiDpcStruct);
				KeSetTargetProcessorDpc(pkDpc, (CCHAR)iCpuNum);
				KeInsertQueueDpc(pkDpc, NULL, NULL);

				// Wait for the DPC to do its job
				KeWaitForSingleObject((PVOID)&pIpiDpcStruct->kEvt, Executive, KernelMode, FALSE, NULL);
				ntStatus = pIpiDpcStruct->ioSb.Status;
				if (!NT_SUCCESS(ntStatus)) break;
			}
			pIrp->IoStatus.Information = 0;
			break;
			
		#pragma endregion

		#pragma region Buffer management IOCTLs
		// Free the previous allocated PT buffer for one or more CPUs (this should be the first Buffer IoCtl due to IOCTL_PTDRV_CLEAR_TRACE Ioctl code)
		case IOCTL_PTDRV_FREE_BUFFERS: {
			// Input buffer:  a DWORD or QWORD that contains the CPU affinity mask
			// Output buffer: None
			lpInBuff = pIrp->AssociatedIrp.SystemBuffer;
			if (dwInBuffSize == sizeof(DWORD))
				kTargetCpusAffinity = (KAFFINITY)(*(DWORD*)lpInBuff);
			else if (dwInBuffSize >= sizeof(KAFFINITY))
				kTargetCpusAffinity = (*(KAFFINITY*)lpInBuff);
			else {
				ntStatus = STATUS_INVALID_BUFFER_SIZE;
				break;
			}
			ntStatus = FreeCpuUserBuffers(kTargetCpusAffinity);
			if (NT_SUCCESS(ntStatus)) g_pDrvData->bManualAllocBuff = FALSE;
			break;
		}

		// Allocate the PT buffer for one or more CPUs
		case IOCTL_PTDRV_ALLOC_BUFFERS: {
			// Input buffer:  a partial PT_USER_REQ that describes the allocation information
			// Output buffer: an array of LPVOID that contains the Virtual addresses of the USER mode buffers
			PT_USER_REQ * ptTraceStruct = NULL;
			BOOLEAN bUseToPA = FALSE;
			DWORD dwNumOfBuffs = 0;
			LPVOID lpBuffArray = NULL;
			lpInBuff = pIrp->AssociatedIrp.SystemBuffer;
			lpOutBuff = pIrp->AssociatedIrp.SystemBuffer;

			if (dwInBuffSize < FIELD_OFFSET(PT_USER_REQ, dwProcessId)) {
				ntStatus = STATUS_INVALID_BUFFER_SIZE;
				break;
			} else
				ptTraceStruct = (PT_USER_REQ*)lpInBuff;

			// Verify the CPU mask affinity
			kTargetCpusAffinity = (KAFFINITY)ptTraceStruct->kCpuAffinity;
			if ((kSysCpusAffinity | kTargetCpusAffinity) != kSysCpusAffinity) {
				ntStatus = STATUS_INVALID_PARAMETER;
				break;
			}

			// Count the number of CPU specified here:
			for (int i = 0; i < sizeof(kTargetCpusAffinity) * 8; i++)
				if (ptTraceStruct->kCpuAffinity & (1i64 << i)) dwNumOfBuffs++;

			if (dwOutBuffSize < dwNumOfBuffs * sizeof(LPVOID)) {
				ntStatus = STATUS_INVALID_BUFFER_SIZE;
				break;
			}
			// Round up buffer size to be page aligned
			ptTraceStruct->dwTraceSize = ROUND_TO_PAGES(ptTraceStruct->dwTraceSize);

			// Consider the dwOptsMask as a bitmask and even as a simple BOOLEAN value
			bUseToPA = (ptTraceStruct->dwOptsMask == 1) || (ptTraceStruct->dwOptsMask & PT_ENABLE_TOPA_MASK);
			ntStatus = AllocateCpuUserBuffers(ptTraceStruct->kCpuAffinity, ptTraceStruct->dwTraceSize, &lpBuffArray, NULL, bUseToPA);
			if (NT_SUCCESS(ntStatus) && lpBuffArray) {
				RtlCopyMemory(lpOutBuff, lpBuffArray, dwNumOfBuffs * sizeof(LPVOID));
				pIrp->IoStatus.Information = dwNumOfBuffs * sizeof(LPVOID);
				g_pDrvData->bManualAllocBuff = TRUE;
			} 
			if (lpBuffArray) ExFreePool(lpBuffArray);
			break;
		}
		#pragma endregion

		#pragma region PMI Callbacks IOCTLs
		case IOCTL_PTDRV_REGISTER_PMI_ROUTINE: {
			// Input buffer: a PT_PMI_USER_CALLBACK data structure
			// Output buffer: None
			PPT_PMI_USER_CALLBACK pCallbackDesc = NULL;
			PETHREAD peThread = NULL;
			
			if (dwInBuffSize < sizeof(PT_PMI_USER_CALLBACK)) {
				ntStatus = STATUS_INVALID_BUFFER_SIZE;
				break;
			} else
				pCallbackDesc = (PPT_PMI_USER_CALLBACK)pIrp->AssociatedIrp.SystemBuffer;

			// Check the CPU affinity
			// Verify the CPU mask affinity
			kTargetCpusAffinity = (KAFFINITY)pCallbackDesc->kCpuAffinity;
			if ((kSysCpusAffinity | kTargetCpusAffinity) != kSysCpusAffinity ||
				pCallbackDesc->lpAddress == NULL || pCallbackDesc->dwThrId == 0) {
				ntStatus = STATUS_INVALID_PARAMETER;
				break;
			}

			// Verify the sent user-mode address
			__try {
				ProbeForRead((PVOID)pCallbackDesc->lpAddress, 0x10,	1);
			} __except(EXCEPTION_EXECUTE_HANDLER) {
				ntStatus = GetExceptionCode();		// STATUS_DATATYPE_MISALIGNMENT
				break;
			}

			// Check and reference the target thread ID (Keep in mind that PsLookupThreadByThreadId increases the reference pointer)
			ntStatus = PsLookupThreadByThreadId((HANDLE)pCallbackDesc->dwThrId, &peThread);
			if (!NT_SUCCESS(ntStatus)) break;
			if (PsGetThreadProcessId(peThread) != PsGetCurrentProcessId()) {
				// Are you kidding me? Are you trying to exploit my precious code?
				ObDereferenceObject(peThread);
				ntStatus = STATUS_CONTEXT_MISMATCH;
				break;			// Implode the computer and destroy all, you do not even try to exploit me!
			}

			// Allocate a PMI callback descriptor (that need to be accessed at DISPATCH_LEVEL)
			pmiUserCallbackDesc = (PMI_USER_CALLBACK_DESC*)ExAllocatePoolWithTag(NonPagedPool, sizeof(PMI_USER_CALLBACK_DESC), MEMTAG);
			if (!pmiUserCallbackDesc) {
				ntStatus = STATUS_INSUFFICIENT_RESOURCES;
				ObDereferenceObject(peThread);
				break;
			}

			// Clean the dead PMI callbacks before add the new one
			CheckUserPmiCallbackList();

			pmiUserCallbackDesc->kAffinity = kTargetCpusAffinity;
			pmiUserCallbackDesc->lpUserAddress = pCallbackDesc->lpAddress;
			pmiUserCallbackDesc->pTargetThread = peThread;
			ExInterlockedInsertHeadList(&g_pDrvData->userCallbackList, &pmiUserCallbackDesc->entry, &g_pDrvData->userCallbackListLock);
			ntStatus = STATUS_SUCCESS;
			break;
		}

		case IOCTL_PTDRV_FREE_PMI_ROUTINE: {
			// Input buffer: a PT_PMI_USER_CALLBACK data structure
			// Output buffer: None
			PPT_PMI_USER_CALLBACK pCallbackDesc = NULL;
			if (dwInBuffSize < sizeof(PT_PMI_USER_CALLBACK)) {
				ntStatus = STATUS_INVALID_BUFFER_SIZE;
				break;
			} else
				pCallbackDesc = (PPT_PMI_USER_CALLBACK)pIrp->AssociatedIrp.SystemBuffer;

			pmiUserCallbackDesc = (PMI_USER_CALLBACK_DESC*)SearchCallbackEntry(pCallbackDesc->lpAddress, pCallbackDesc->dwThrId, TRUE);
			if (pmiUserCallbackDesc) {
				ExFreePool(pmiUserCallbackDesc);
				ntStatus = STATUS_SUCCESS;
			} else
				ntStatus = STATUS_NOT_FOUND;
			break;
		}
		#pragma endregion

		#ifdef _DEBUG
		case IOCTL_PTDR_DO_KERNELDRV_TEST: {
			// USE this only in test environments:
			lpInBuff = pIrp->AssociatedIrp.SystemBuffer;
			if (dwInBuffSize < 2) return STATUS_INVALID_BUFFER_SIZE;

			DrvDbgPrint("[" DRV_NAME "] Received special Debug IOCTL. Do not use this in production environments!\r\n");
			ntStatus = DoDriverTraceTest((LPTSTR)lpInBuff);
			if (!NT_SUCCESS(ntStatus)) 
				DrvDbgPrint("[" DRV_NAME "] The Kernel mode tracing test has failed with 0x%08X status.", ntStatus);
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
	pIrp->IoStatus.Status = ntStatus;
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
				RtlCopyMemory(ptDesc.Ranges, ptTraceUserStruct->IpFiltering.Ranges, sizeof(PT_TRACE_RANGE) * 4); // should be ptDesc.dwNumOfRanges

			// user input validated in DriverIo dispatch function
			ntStatus = StartCpuTrace(ptDesc, (QWORD)ptTraceUserStruct->dwTraceSize);
			break;
		}
		case DPC_TYPE_PAUSE_PT: {
			BOOLEAN bPause = (BOOLEAN)SysArg1;
			ntStatus = PauseResumeTrace(bPause);
			break;
		}
		case DPC_TYPE_CLEAR_PT: 
			ntStatus = StopAndDisablePt();
			if (!g_pDrvData->bManualAllocBuff && NT_SUCCESS(ntStatus))
				ntStatus = FreeCpuResources(dwCpuId);
			break;
	}

	if (SysArg2) ObDereferenceObject(SysArg2);

	// Raise the event
	pIpiDpcStruct->ioSb.Status = ntStatus;
	KeSetEvent(&pIpiDpcStruct->kEvt, IO_NO_INCREMENT, FALSE);
}

#pragma code_seg()
